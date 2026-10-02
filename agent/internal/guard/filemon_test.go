//go:build linux

package guard

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/alinksec/alinksec-agent/internal/config"
)

func protectionLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func testFileRule(path string, restore bool) config.FileRule {
	actions := []string{"alert"}
	if restore {
		actions = append(actions, "restore")
	}
	return config.FileRule{ID: "file-test", Enabled: true, Severity: 3, Match: config.FileMatch{Paths: []string{path}}, Actions: actions}
}

func putFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestFileMonitorAlertsWithoutRestoringAndDeduplicates(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config")
	putFile(t, path, "SECRET ORIGINAL")
	m := newFileMonitor(root, protectionLogger())
	m.update([]config.FileRule{testFileRule(path, false)})
	if events := m.check(); len(events) != 0 {
		t.Fatalf("baseline produced events: %v", events)
	}
	putFile(t, path, "SECRET MODIFIED")
	events := m.check()
	if len(events) != 1 || events[0].GetType() != "file_tamper" || events[0].GetActionTaken() != "alert_only" || strings.Contains(events[0].GetDetail(), "SECRET") {
		t.Fatalf("unexpected event: %v", events)
	}
	if data, _ := os.ReadFile(path); string(data) != "SECRET MODIFIED" {
		t.Fatal("alert-only rule restored content")
	}
	if len(m.check()) != 0 {
		t.Fatal("unchanged tampering must not repeat alerts")
	}
	putFile(t, path, "SECRET ORIGINAL")
	m.check()
	putFile(t, path, "SECRET MODIFIED")
	if len(m.check()) != 1 {
		t.Fatal("new tampering after recovery should alert")
	}
}

func TestFileMonitorRestoresContentModeDeletionAndSymlinkSafely(t *testing.T) {
	for _, change := range []string{"content", "mode", "delete", "symlink", "oversized"} {
		t.Run(change, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "config")
			outside := filepath.Join(t.TempDir(), "outside")
			putFile(t, path, "ORIGINAL")
			putFile(t, outside, "OUTSIDE")
			before, _ := os.Stat(path)
			m := newFileMonitor(root, protectionLogger())
			rule := testFileRule(path, true)
			rule.Match.MaxFileBytes = 16
			m.update([]config.FileRule{rule})
			m.check()
			switch change {
			case "content":
				putFile(t, path, "CHANGED")
			case "mode":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "delete":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				os.Remove(path)
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				putFile(t, path, strings.Repeat("x", 32))
			}
			events := m.check()
			if len(events) != 1 || events[0].GetActionTaken() != "restored" {
				t.Fatalf("restore event = %v", events)
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != "ORIGINAL" {
				t.Fatalf("restored data = %q, %v", data, err)
			}
			after, _ := os.Lstat(path)
			uid, gid := fileOwner(before)
			newUID, newGID := fileOwner(after)
			if !after.Mode().IsRegular() || after.Mode().Perm() != before.Mode().Perm() || uid != newUID || gid != newGID {
				t.Fatal("restoration did not preserve file metadata")
			}
			if data, _ := os.ReadFile(outside); string(data) != "OUTSIDE" {
				t.Fatal("symlink target changed")
			}
			if len(m.check()) != 0 {
				t.Fatal("restored file should not alert again")
			}
		})
	}
}

func TestFileBaselineSurvivesRestartAndDisabledRuleAcceptsChanges(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config")
	putFile(t, path, "ORIGINAL")
	rule := testFileRule(path, true)
	m := newFileMonitor(root, protectionLogger())
	m.update([]config.FileRule{rule})
	m.check()
	putFile(t, path, "TAMPERED")
	m = newFileMonitor(root, protectionLogger())
	m.update([]config.FileRule{rule})
	if e := m.check(); len(e) != 1 || e[0].GetActionTaken() != "restored" {
		t.Fatalf("restart adopted tampered baseline: %v", e)
	}
	rule.Enabled = false
	m.update([]config.FileRule{rule})
	putFile(t, path, "APPROVED")
	if len(m.check()) != 0 {
		t.Fatal("disabled rule should not monitor")
	}
	rule.Enabled = true
	m.update([]config.FileRule{rule})
	if len(m.check()) != 0 {
		t.Fatal("reenabling should capture fresh baseline")
	}
	putFile(t, path, "TAMPERED")
	m.check()
	if data, _ := os.ReadFile(path); string(data) != "APPROVED" {
		t.Fatal("reenabling did not adopt approved content")
	}
}

func TestFileMonitorRestoresOriginallyAbsentPathAndRejectsCorruptBaseline(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "absent")
	rule := testFileRule(path, true)
	m := newFileMonitor(root, protectionLogger())
	m.update([]config.FileRule{rule})
	m.check()
	putFile(t, path, "NEW")
	if e := m.check(); len(e) != 1 || e[0].GetActionTaken() != "restored" {
		t.Fatalf("creation event = %v", e)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("unexpected created file was not removed")
	}
	m.update(nil)
	putFile(t, path, "ORIGINAL")
	m.update([]config.FileRule{rule})
	m.check()
	var watch *watchedFile
	for _, w := range m.files {
		watch = w
	}
	putFile(t, filepath.Join(m.dir, watch.key+".bin"), "CORRUPT")
	putFile(t, path, "CHANGED")
	if e := m.check(); len(e) != 1 || e[0].GetActionTaken() != "restore_failed" {
		t.Fatalf("corrupt content was restored: %v", e)
	}
	putFile(t, filepath.Join(m.dir, watch.key+".json"), "INVALID")
	m = newFileMonitor(root, protectionLogger())
	m.update([]config.FileRule{rule})
	if e := m.check(); len(e) != 1 || !strings.Contains(e[0].GetDetail(), "baseline_invalid") {
		t.Fatalf("corrupt metadata was adopted: %v", e)
	}
}

func TestFileMonitorRejectsReplacedParentDirectory(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "protected")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "config")
	putFile(t, path, "ORIGINAL")
	work := t.TempDir()
	rule := testFileRule(path, true)
	m := newFileMonitor(work, protectionLogger())
	m.update([]config.FileRule{rule})
	if e := m.check(); len(e) != 0 {
		t.Fatalf("baseline event = %v", e)
	}
	if err := os.Rename(parent, parent+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	putFile(t, path, "UNRELATED")
	for _, restart := range []bool{false, true} {
		if restart {
			m = newFileMonitor(work, protectionLogger())
			m.update([]config.FileRule{rule})
		}
		if e := m.check(); len(e) != 1 || e[0].GetActionTaken() != "restore_failed" || !strings.Contains(e[0].GetDetail(), "parent_changed") {
			t.Fatalf("replaced parent event = %v", e)
		}
		if data, _ := os.ReadFile(path); string(data) != "UNRELATED" {
			t.Fatal("restoration wrote into replacement directory")
		}
	}
}

func TestProtectionStateReadsAreBoundedAndPolicyUpdatesAreConcurrent(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config")
	putFile(t, path, strings.Repeat("x", 32))
	if _, err := readPrivateLimited(path, 16); err == nil {
		t.Fatal("oversized private state accepted")
	}
	rule := testFileRule(path, false)
	m := newFileMonitor(root, protectionLogger())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			m.update([]config.FileRule{rule})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			m.check()
		}
	}()
	wg.Wait()
}
