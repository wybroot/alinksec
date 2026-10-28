package guard

import (
	"fmt"
	"github.com/alinksec/alinksec-agent/internal/config"
	"github.com/alinksec/alinksec-agent/internal/filewatch"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRecoveryRetainsRepeatedRescanRequests(t *testing.T) {
	root, later, anchor := t.TempDir(), t.TempDir(), t.TempDir()
	for dir, count := range map[string]int{root: 2, later: 24} {
		for n := 0; n < count; n++ {
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprint(n)), []byte("harmless rescan fixture"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	disabled := false
	g := New(&config.DecoyConfig{Enabled: &disabled}, nil, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	defer func() {
		if g.virusRecovery != nil {
			g.virusRecovery.Close()
		}
	}()
	seen := map[string]int{}
	g.SetVirusEngine(func(p string) *pb.VirusFinding { seen[p]++; return nil })
	g.SetVirusRoots([]string{root, later}, nil)
	g.updateFileWatches()
	g.fileEventLoop()
	old := g.virusRecovery
	if old == nil || seen[filepath.Join(root, "0")] != 1 || seen[filepath.Join(root, "1")] != 1 {
		t.Fatal("fixture did not finish the first root while retaining the later traversal")
	}
	late := filepath.Join(root, "created-after-cursor-left")
	if err := os.WriteFile(late, []byte("harmless late recovery fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 2; n++ {
		// A watch configuration change requests recovery without delivering
		// a file event for the newly created file in the already visited root.
		g.watcher.Update([]filewatch.Root{{Path: root, Recursive: true}, {Path: later, Recursive: true}, {Path: filepath.Join(anchor, fmt.Sprint(n))}})
		g.fileEventLoop()
		if g.virusRecovery != old || !g.virusRescan {
			t.Fatal("new rescan restarted or disappeared behind the active traversal")
		}
	}
	for n := 0; n < 10 && g.virusRecovery != nil; n++ {
		g.fileEventLoop()
	}
	if g.virusRecovery != nil || !g.virusRescan || seen[late] != 0 || len(seen) != 26 {
		t.Fatal("first traversal lost progress or the pending recovery request", seen)
	}
	g.fileEventLoop()
	for n := 0; n < 10 && g.virusRecovery != nil; n++ {
		g.fileEventLoop()
	}
	if g.virusRecovery != nil || g.virusRescan || len(seen) != 27 || seen[late] != 1 {
		t.Fatal("coalesced recovery did not cover the previously visited root", seen)
	}
	for p, count := range seen {
		if p != late && count != 2 {
			t.Fatalf("recovery skipped or repeatedly restarted a file: %s count=%d", p, count)
		}
	}
}

func TestRecoveryScopeReplacementClosesOldTraversal(t *testing.T) {
	old, next := t.TempDir(), t.TempDir()
	for n := 0; n < 40; n++ {
		if err := os.WriteFile(filepath.Join(old, fmt.Sprint(n)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	newFile := filepath.Join(next, "new-scope.txt")
	os.WriteFile(newFile, []byte("harmless"), 0600)
	disabled := false
	g := New(&config.DecoyConfig{Enabled: &disabled}, nil, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	seen := map[string]int{}
	g.SetVirusEngine(func(p string) *pb.VirusFinding { seen[p]++; return nil })
	g.SetVirusRoots([]string{old}, nil)
	g.fileEventLoop()
	if g.virusRecovery == nil {
		t.Fatal("fixture did not retain old traversal")
	}
	g.SetVirusRoots([]string{next}, nil)
	g.fileEventLoop()
	if seen[newFile] != 1 {
		t.Fatal("new scope delayed behind old traversal", seen)
	}
	if g.virusRecovery != nil {
		g.virusRecovery.Close()
	}
	enabled := false
	g.SetVirusRoots([]string{next}, func() bool { return enabled })
	g.fileEventLoop()
	late := filepath.Join(next, "created-while-disabled.txt")
	os.WriteFile(late, nil, 0600)
	enabled = true
	g.fileEventLoop()
	if seen[late] != 1 {
		t.Fatal("reenabling unchanged watch roots missed disabled-period files")
	}
	if g.virusRecovery != nil {
		g.virusRecovery.Close()
	}
}

func TestRecoveryVirusProtectionIndependentOfDecoyAndReportsIdentity(t *testing.T) {
	root := t.TempDir()
	enabled := true
	checks := 0
	var events []*pb.RptSecurityEvent
	disabled := false
	g := New(&config.DecoyConfig{Enabled: &disabled}, nil, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)), func(e *pb.RptSecurityEvent) { events = append(events, e) })
	g.SetVirusRoots([]string{root}, func() bool { return enabled })
	g.SetVirusEngine(func(path string) *pb.VirusFinding {
		checks++
		return &pb.VirusFinding{Path: path, Name: "Harmless", Engine: "hash", Sha256: "digest", Severity: pb.Severity_SEV_HIGH, ActionTaken: "alert_only", ActionError: "budget_exhausted"}
	})
	g.virusRescan = true
	g.fileEventLoop()
	path := filepath.Join(root, "new.sh")
	os.WriteFile(path, []byte("harmless"), 0600)
	g.virusRescan = true
	g.fileEventLoop()
	if checks != 1 || len(events) != 1 || events[0].Severity != pb.Severity_SEV_HIGH || events[0].Type != "virus" {
		t.Fatal(checks, events)
	}
	g.fileEventLoop()
	if checks != 1 {
		t.Fatal("unchanged file rescanned")
	}
	enabled = false
	os.WriteFile(path, []byte("changed harmless"), 0600)
	g.virusRescan = true
	g.fileEventLoop()
	if checks != 1 {
		t.Fatal("disabled policy checked file")
	}
	enabled = true
	g.fileEventLoop()
	if checks != 2 {
		t.Fatal("reenabled policy missed changes")
	}
}
func TestPeriodicSnapshotBoundsDirectoriesAndUsesNanosecondTime(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 10; i++ {
		os.Mkdir(filepath.Join(root, string(rune('a'+i))), 0700)
	}
	left := 3
	virusSnapshot(root, &left, time.Now().Add(time.Second))
	if left != 0 {
		t.Fatal("directory entries not bounded", left)
	}
	left = 100
	path := filepath.Join(root, "same.sh")
	os.WriteFile(path, []byte("old"), 0600)
	stamp := time.Unix(100, 100)
	os.Chtimes(path, stamp, stamp)
	first := virusSnapshot(root, &left, time.Now().Add(time.Second))
	stamp = time.Unix(100, 500000)
	os.Chtimes(path, stamp, stamp)
	left = 100
	next := virusSnapshot(root, &left, time.Now().Add(time.Second))
	if len(diffSnapshot(first, next).Modified) != 1 {
		t.Fatal("sub-second modification missed")
	}
}
