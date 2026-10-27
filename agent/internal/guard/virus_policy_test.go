package guard

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/alinksec/alinksec-agent/internal/config"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func TestVirusBatchRechecksScopeAfterPolicyReplacement(t *testing.T) {
	root := t.TempDir()
	kept := filepath.Join(root, "kept")
	if err := os.Mkdir(kept, 0700); err != nil {
		t.Fatal(err)
	}
	first, revoked, current := filepath.Join(root, "in-flight"), filepath.Join(root, "revoked"), filepath.Join(kept, "current")
	for _, p := range []string{first, revoked, current} {
		if err := os.WriteFile(p, []byte("harmless policy boundary fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	disabled := false
	var reports []*pb.RptSecurityEvent
	g := New(&config.DecoyConfig{Enabled: &disabled}, nil, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)), func(e *pb.RptSecurityEvent) { reports = append(reports, e) })
	seen := map[string]int{}
	g.SetVirusEngine(func(p string) *pb.VirusFinding {
		seen[p]++
		if p == first {
			// The first check has already started. Only the nested root remains
			// authorized when the next file is about to be dispatched.
			g.SetVirusRoots([]string{kept}, nil)
		}
		return &pb.VirusFinding{Path: p, Name: "Harmless.PolicyBoundary", Engine: "hash", ActionTaken: "alert_only"}
	})
	g.SetVirusRoots([]string{root}, nil)
	g.virusRunning, g.virusScope = true, []string{root}
	g.eventPending = []string{first, revoked, current}
	g.fileEventLoop()
	if seen[first] != 1 || seen[revoked] != 0 || seen[current] != 1 || len(reports) != 2 {
		t.Fatal("scope replacement did not apply before subsequent event checks", seen, len(reports))
	}
	// The next dispatch must also replace recovery scope, without losing the
	// already-started finding or access to the retained nested root.
	g.fileEventLoop()
	if g.virusRecovery != nil {
		g.virusRecovery.Close()
	}
	if seen[first] != 1 || seen[revoked] != 0 || seen[current] != 2 {
		t.Fatal("recovery used revoked scope or lost the current scope", seen)
	}
}

func TestVirusBatchRechecksDisablement(t *testing.T) {
	root := t.TempDir()
	var paths []string
	for n := 0; n < 3; n++ {
		p := filepath.Join(root, fmt.Sprintf("file-%d", n))
		if err := os.WriteFile(p, nil, 0600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	disabled, enabled, turnOff := false, true, true
	g := New(&config.DecoyConfig{Enabled: &disabled}, nil, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	seen := map[string]int{}
	g.SetVirusEngine(func(p string) *pb.VirusFinding {
		seen[p]++
		if turnOff {
			enabled, turnOff = false, false
		}
		return nil
	})
	g.SetVirusRoots([]string{root}, func() bool { return enabled })
	g.virusRunning, g.virusScope = true, []string{root}
	g.eventPending = append([]string(nil), paths...)
	g.fileEventLoop()
	if len(seen) != 1 || seen[paths[0]] != 1 {
		t.Fatal("files dispatched after realtime disablement", seen)
	}
	g.fileEventLoop()
	if g.virusRunning || g.virusRecovery != nil {
		t.Fatal("disabled protection retained active recovery")
	}
	enabled = true
	g.fileEventLoop()
	if g.virusRecovery != nil {
		g.virusRecovery.Close()
	}
	for _, p := range paths {
		want := 1
		if p == paths[0] {
			want++
		}
		if seen[p] != want {
			t.Fatal("reenabling failed to recover a skipped file", p, seen)
		}
	}
}

func TestVirusRecoveryRechecksScopeBeforeNextFile(t *testing.T) {
	old, next := t.TempDir(), t.TempDir()
	for n := 0; n < 20; n++ {
		if err := os.WriteFile(filepath.Join(old, fmt.Sprintf("old-%02d", n)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	current := filepath.Join(next, "current")
	if err := os.WriteFile(current, nil, 0600); err != nil {
		t.Fatal(err)
	}
	disabled := false
	g := New(&config.DecoyConfig{Enabled: &disabled}, nil, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	oldChecks, currentChecks := 0, 0
	g.SetVirusEngine(func(p string) *pb.VirusFinding {
		if p == current {
			currentChecks++
		} else {
			oldChecks++
			if oldChecks == 1 {
				g.SetVirusRoots([]string{next}, nil)
			}
		}
		return nil
	})
	g.SetVirusRoots([]string{old}, nil)
	defer func() {
		if g.virusRecovery != nil {
			g.virusRecovery.Close()
		}
	}()
	g.fileEventLoop()
	if oldChecks != 1 {
		t.Fatal("recovery dispatched further revoked files", oldChecks)
	}
	g.fileEventLoop()
	if oldChecks != 1 || currentChecks != 1 {
		t.Fatal("new recovery scope did not replace old traversal", oldChecks, currentChecks)
	}
}
