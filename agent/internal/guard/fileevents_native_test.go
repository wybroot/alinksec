//go:build linux || windows

package guard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/config"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/virusscan"
)

func TestNativeFileEvents(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "watched")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	disabled := false
	enabled := true
	var reports []*pb.RptSecurityEvent
	g := New(&config.DecoyConfig{Enabled: &disabled}, nil, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)), func(e *pb.RptSecurityEvent) { reports = append(reports, e) })
	harmless := []byte("alinksec native event harmless hash fixture")
	sum := sha256.Sum256(harmless)
	if err := os.MkdirAll(virusscan.DBDir(g.workDir), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(virusscan.DBDir(g.workDir), "manifest.json"), []byte(`{"db_version":"native-events","hash_count":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(virusscan.DBDir(g.workDir), "hashes.txt"), []byte(hex.EncodeToString(sum[:])+" Harmless.NativeEvent 3\n"), 0600); err != nil {
		t.Fatal(err)
	}
	engine := virusscan.NewEngine(g.workDir, g.log)
	seen := map[string]int{}
	g.SetVirusRoots([]string{root}, func() bool { return enabled })
	g.SetVirusEngine(func(p string) *pb.VirusFinding {
		if st, e := os.Lstat(p); e == nil && st.Mode().IsRegular() {
			seen[p]++
		}
		return engine.CheckRealtime(p, g.workDir)
	})
	protected := filepath.Join(root, "protected.txt")
	os.WriteFile(protected, []byte("original"), 0600)
	g.UpdateProtection([]config.FileRule{{ID: "native-integrity", Enabled: true, Severity: 3, Match: config.FileMatch{Paths: []string{protected}}, Actions: []string{"alert"}}}, nil)
	g.fileLoop()
	g.updateFileWatches()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { g.watcher.Run(ctx); close(done) }()
	defer func() {
		cancel()
		<-done
		if g.virusRecovery != nil {
			g.virusRecovery.Close()
		}
	}()
	checks := []string{}
	wait := func(name string, predicate func() bool) {
		t.Helper()
		end := time.Now().Add(12 * time.Second)
		for time.Now().Before(end) {
			g.updateFileWatches()
			g.fileEventLoop()
			if predicate() {
				checks = append(checks, name)
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("%s: status=%s seen=%v", name, g.FileWatchStatus(), seen)
	}
	wait("native-registration", func() bool { return g.watcher.Status().Watches >= 2 && seen[protected] > 0 })
	path := filepath.Join(root, "sample.txt")
	write := func(p, s string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(path, "create")
	wait("create-to-virus-check", func() bool { return seen[path] > 0 })
	before := seen[path]
	write(path, "modified-content")
	wait("write-to-virus-check", func() bool { return seen[path] > before })
	before = seen[path]
	tmp := filepath.Join(parent, "replacement")
	write(tmp, "atomic-replacement")
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	wait("atomic-replace", func() bool { return seen[path] > before })
	renamed := filepath.Join(root, "renamed.txt")
	if err := os.Rename(path, renamed); err != nil {
		t.Fatal(err)
	}
	wait("rename-destination", func() bool { return seen[renamed] > 0 })
	write(protected, "tampered")
	wait("event-to-integrity-alert", func() bool {
		for _, r := range reports {
			if r.GetType() == "file_tamper" {
				return true
			}
		}
		return false
	})
	sub := filepath.Join(root, "new-subtree")
	os.Mkdir(sub, 0700)
	nested := filepath.Join(sub, "already-created.txt")
	write(nested, "created-before-watch-registration")
	wait("new-subtree-recovery", func() bool { return seen[nested] > 0 })
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	os.Mkdir(root, 0700)
	recreated := filepath.Join(root, "recreated.txt")
	write(recreated, "recreated-root")
	wait("root-delete-recreate", func() bool { return seen[recreated] > 0 })
	hit := filepath.Join(root, "harmless-hash.sample")
	write(hit, string(harmless))
	wait("native-event-to-hash-quarantine-and-report", func() bool {
		for _, r := range reports {
			if r.GetType() == "virus" {
				return true
			}
		}
		return false
	})
	if _, err := os.Lstat(hit); !os.IsNotExist(err) {
		t.Fatal("hash fixture was not quarantined", err)
	}
	enabled = false
	g.updateFileWatches()
	disabledPath := filepath.Join(root, "disabled.txt")
	write(disabledPath, "disabled")
	for n := 0; n < 5; n++ {
		g.fileEventLoop()
		time.Sleep(20 * time.Millisecond)
	}
	if seen[disabledPath] != 0 {
		t.Fatal("disabled virus policy executed")
	}
	checks = append(checks, "disabled-policy-no-virus-check")
	enabled = true
	g.updateFileWatches()
	wait("reenable-recovery", func() bool { return seen[disabledPath] > 0 })
	other := t.TempDir()
	g.SetVirusRoots([]string{other}, func() bool { return true })
	g.UpdateProtection(nil, nil)
	g.updateFileWatches()
	old := filepath.Join(root, "removed-scope.txt")
	write(old, "must-not-scan")
	current := filepath.Join(other, "current.txt")
	write(current, "current-scope")
	wait("policy-replacement-current-scope", func() bool { return seen[current] > 0 })
	if seen[old] != 0 {
		t.Fatal("removed virus root was scanned")
	}
	checks = append(checks, "removed-scope-not-scanned")
	decoyPolicy := &config.DecoyConfig{Enabled: &enabled, Dirs: []string{other}, WatchTrees: []string{other}, CountPerDir: 1, Response: "alert_only"}
	decoyPolicy.Normalize()
	g.UpdatePolicy(decoyPolicy, nil)
	g.updateFileWatches()
	decoys := newDecoyManager(decoyPolicy, g.workDir).knownDecoys()
	if len(decoys) != 1 {
		t.Fatal("native decoy fixture not deployed", decoys)
	}
	write(decoys[0], "harmless decoy tampering")
	wait("native-event-to-decoy-alert", func() bool {
		for _, r := range reports {
			if r.GetType() == "decoy_tamper" && r.GetSeverity() == pb.Severity_SEV_CRITICAL {
				return true
			}
		}
		return false
	})
	cancel()
	select {
	case <-done:
		checks = append(checks, "native-handle-cleanup")
	case <-time.After(5 * time.Second):
		t.Fatal("watcher shutdown timeout")
	}
	if dest := os.Getenv("ALINKSEC_FILE_WATCH_EVIDENCE_FILE"); dest != "" {
		var status any
		json.Unmarshal([]byte(g.FileWatchStatus()), &status)
		data, _ := json.MarshalIndent(map[string]any{"passed": true, "os": runtime.GOOS, "arch": runtime.GOARCH, "checks": checks, "status": status}, "", "  ")
		if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dest, append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
