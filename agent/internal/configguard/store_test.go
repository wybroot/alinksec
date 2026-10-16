package configguard

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/config"
)

func testStore(t *testing.T) (*Store, string, string, []byte) {
	t.Helper()
	work := t.TempDir()
	path := filepath.Join(work, "agent.yml")
	good := []byte("server_addr: trusted.example:9443\nenroll_token: ENROLL-do-not-report\ndecoy:\n  enabled: false\n")
	if err := os.WriteFile(path, good, 0600); err != nil {
		t.Fatal(err)
	}
	if err := protectFile(path); err != nil {
		t.Fatal(err)
	}
	s, c, err := Open(work, path)
	if err != nil {
		t.Fatal(err)
	}
	if c.ServerAddr != "trusted.example:9443" {
		t.Fatal(c.ServerAddr)
	}
	t.Cleanup(s.Close)
	if err := s.SetPolicy(nil, ""); err != nil {
		t.Fatal(err)
	}
	return s, work, path, good
}

func TestTamperSameLengthSameMtimeAndRestartUsesPinnedAddress(t *testing.T) {
	s, work, path, good := testStore(t)
	i, _ := os.Stat(path)
	bad := bytes.ReplaceAll(good, []byte("trusted"), []byte("hostile"))
	if len(bad) != len(good) {
		t.Fatal("fixture must preserve length")
	}
	if err := os.WriteFile(path, bad, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, i.ModTime(), i.ModTime()); err != nil {
		t.Fatal(err)
	}
	s.Close() // No in-process check; startup must reject the modified source.
	reopened, cfg, err := Open(work, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if cfg.ServerAddr != "trusted.example:9443" {
		t.Fatalf("modified endpoint accepted: %s", cfg.ServerAddr)
	}
	if b, _ := os.ReadFile(path); !bytes.Equal(b, good) {
		t.Fatal("safe shadow was not restored")
	}
	events := reopened.Events()
	if len(events) != 1 || events[0].ObservedSHA256 != sum(bad) || events[0].Shadow != "restored" {
		t.Fatalf("events=%+v", events)
	}
	encoded, _ := json.Marshal(events)
	if bytes.Contains(encoded, []byte("ENROLL-do-not-report")) || bytes.Contains(encoded, []byte("hostile.example")) {
		t.Fatal("configuration plaintext leaked in evidence")
	}
	if err := reopened.Check(); err != nil {
		t.Fatal(err)
	}
	if len(reopened.Events()) != 1 {
		t.Fatal("healthy recheck duplicated event")
	}
}

func TestMissingAndLinkedShadowsNeverRedirectWrites(t *testing.T) {
	s, _, path, good := testStore(t)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := s.Check(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); !bytes.Equal(b, good) {
		t.Fatal("missing shadow not restored")
	}
	target := filepath.Join(t.TempDir(), "unrelated")
	const sentinel = "do not read or overwrite this target"
	if err := os.WriteFile(target, []byte(sentinel), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := s.Check(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != sentinel {
		t.Fatal("symlink target was modified")
	}
	if got := s.Events(); got[len(got)-1].Shadow != "blocked" {
		t.Fatalf("unsafe repair falsely reported: %+v", got)
	}
	n := len(s.Events())
	if err := s.Check(); err != nil {
		t.Fatal(err)
	}
	if len(s.Events()) != n {
		t.Fatal("persistent failure emitted duplicate events")
	}
}

func TestPinnedPolicyAndVersionsSurviveShadowChangesAndDeletion(t *testing.T) {
	s, work, path, _ := testStore(t)
	good := []byte(`{"virus_realtime":{"enabled":true,"action":"quarantine"},"virus_whitelist":[]}`)
	if err := s.SetPolicy(good, "authenticated-v3"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "policy.json"), []byte(`{"virus_realtime":{"enabled":false}}`), 0600); err != nil {
		t.Fatal(err)
	}
	s.Close()
	next, _, err := Open(work, path)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	data, v, ready := next.Policy()
	if !ready || v != "authenticated-v3" || !bytes.Equal(data, good) {
		t.Fatal("policy shadow changed active policy")
	}
	if err := os.Remove(filepath.Join(work, "policy.json")); err != nil {
		t.Fatal(err)
	}
	if err := next.Check(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(work, "policy.json")); !bytes.Equal(b, good) {
		t.Fatal("policy deletion not recovered")
	}
}

func TestRemovedOrCorruptTrustedStateCannotBecomeNewBaseline(t *testing.T) {
	for _, kind := range []string{"missing", "corrupt", "wrong-path"} {
		t.Run(kind, func(t *testing.T) {
			s, work, path, _ := testStore(t)
			s.Close()
			switch kind {
			case "missing":
				if err := os.Remove(s.recordPath()); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(s.recordPath(), []byte(`{"version":1}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong-path":
				path = filepath.Join(work, "other.yml")
			}
			if opened, _, err := Open(work, path); err == nil {
				opened.Close()
				t.Fatal("invalid trusted state silently re-pinned")
			}
		})
	}
}

func TestRuntimeTrustedStateCorruptionRecoveredFromMemory(t *testing.T) {
	s, work, path, good := testStore(t)
	if err := os.WriteFile(s.recordPath(), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Check(); err != nil {
		t.Fatal(err)
	}
	if s.Events()[0].File != "trusted_state" {
		t.Fatal("missing trusted-state event")
	}
	s.Close()
	next, cfg, err := Open(work, path)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if cfg.ServerAddr != "trusted.example:9443" || !bytes.Equal(next.r.Agent, good) {
		t.Fatal("corrupt state replaced pinned config")
	}
}

func TestEnrollmentSecretClearedFromBothCopies(t *testing.T) {
	s, _, path, _ := testStore(t)
	if err := s.ClearEnrollToken(); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{path, s.recordPath()} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte("ENROLL-do-not-report")) {
			t.Fatal("bootstrap credential retained")
		}
	}
}

func TestCreatePinsEnrollmentCAAndRefusesExistingInstall(t *testing.T) {
	work := filepath.Join(t.TempDir(), "new", "nested", "work")
	path := filepath.Join(work, "agent.yml")
	s, c, err := Create(work, path, &config.Config{ServerAddr: "server.example:9443", EnrollToken: "bootstrap", EnrollCAFile: "/admin/ca.crt"})
	if err != nil {
		t.Fatal(err)
	}
	if c.EnrollCAFile != "/admin/ca.crt" {
		t.Fatal("initial CA reference lost")
	}
	if err := s.ClearEnrollToken(); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if s, _, err := Create(work, path, &config.Config{ServerAddr: "other.example:9443"}); err == nil {
		s.Close()
		t.Fatal("installer replaced existing trusted endpoint")
	}
}

func TestFailedEvidenceCommitIsRetriedWithoutNewChanges(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("POSIX directory mode failure fixture")
	}
	s, work, path, _ := testStore(t)
	target := filepath.Join(t.TempDir(), "unrelated")
	if err := os.WriteFile(target, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(s.dir, 0777); err != nil {
		t.Fatal(err)
	}
	if err := s.Check(); err == nil {
		t.Fatal("unsafe evidence directory was writable")
	}
	if err := os.Chmod(s.dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.Check(); err != nil {
		t.Fatal(err)
	}
	id := s.Events()[0].ID
	s.Close()
	next, _, err := Open(work, path)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if next.Events()[0].ID != id {
		t.Fatal("failed evidence commit was not retried durably")
	}
}

func TestConcurrentPolicyCommitAndCheckKeepsLatestSnapshot(t *testing.T) {
	s, _, _, _ := testStore(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.Check(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.SetPolicy([]byte(`{"virus_whitelist":[]}`), "v-next"); err != nil {
			t.Error(err)
		}
	}()
	wg.Wait()
	data, v, _ := s.Policy()
	if v != "v-next" || string(data) != `{"virus_whitelist":[]}` {
		t.Fatal("new mTLS policy lost")
	}
}

func TestMetadataAndInputBoundaries(t *testing.T) {
	if runtime.GOOS == "linux" {
		s, _, path, _ := testStore(t)
		if err := os.Chmod(path, 0666); err != nil {
			t.Fatal(err)
		}
		if err := s.Check(); err != nil {
			t.Fatal(err)
		}
		if err := privateFile(path); err != nil {
			t.Fatal(err)
		}
		if s.Events()[0].Reason != "unsafe_permissions" {
			t.Fatal("mode drift not detected")
		}
	}
	work := t.TempDir()
	path := filepath.Join(work, "agent.yml")
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), 65537), 0600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if s, _, err := Open(work, path); err == nil {
		s.Close()
		t.Fatal("oversize config accepted")
	}
	if time.Since(start) > time.Second {
		t.Fatal("oversize read was not bounded")
	}
}

func TestEventRetentionKeepsLatestStableIdentities(t *testing.T) {
	s, work, path, _ := testStore(t)
	var ids []string
	for i := 0; i < MaxEvents+5; i++ {
		if err := os.WriteFile(path, bytes.Repeat([]byte("x"), i+1), 0600); err != nil {
			t.Fatal(err)
		}
		if err := s.Check(); err != nil {
			t.Fatal(err)
		}
		events := s.Events()
		ids = append(ids, events[len(events)-1].ID)
	}
	s.Close()
	next, _, err := Open(work, path)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	events := next.Events()
	if len(events) != MaxEvents {
		t.Fatalf("retained %d events, expected %d", len(events), MaxEvents)
	}
	for i, event := range events {
		if event.ID != ids[i+5] {
			t.Fatal("restart changed retained identity or evicted the wrong event")
		}
	}
}

func TestEscapedLongPathsAndFullPolicyFitDurableAndTransportLimits(t *testing.T) {
	s, _, _, _ := testStore(t)
	if err := s.SetPolicy(bytes.Repeat([]byte(" "), MaxPolicyBytes), "max-policy"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxEvents; i++ {
		if err := s.event("agent.yml", string(bytes.Repeat([]byte("&"), 4096)), "content_changed", sum([]byte("expected")), sum([]byte{byte(i)}), "blocked"); err != nil {
			t.Fatal(err)
		}
	}
	for _, event := range s.Events() {
		data, err := json.Marshal(event)
		if err != nil || len(data) > 8192 || !event.PathTruncated {
			t.Fatal("long-path evidence cannot be accepted by the server")
		}
	}
	if err := s.persist(); err != nil {
		t.Fatalf("full policy and bounded event retention cannot coexist: %v", err)
	}
}
