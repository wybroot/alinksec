//go:build linux

package guard

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/alinksec/alinksec-agent/internal/config"
	"github.com/alinksec/alinksec-agent/internal/filewatch"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func TestRecoveryReportsDirectoryReplacementAndFreshSweepRecovers(t *testing.T) {
	root, other := t.TempDir(), t.TempDir()
	write := func(dir string, names ...string) {
		t.Helper()
		for _, name := range names {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("harmless recovery fixture"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	write(root, "one", "two")
	write(other, "later-one", "later-two")
	disabled := false
	g := New(&config.DecoyConfig{Enabled: &disabled}, nil, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	defer func() {
		if g.virusRecovery != nil {
			g.virusRecovery.Close()
		}
	}()
	g.SetVirusRoots([]string{root, other}, nil)
	var checks []string
	changed := false
	g.SetVirusEngine(func(p string) *pb.VirusFinding {
		checks = append(checks, p)
		if !changed && filewatch.Within(p, root) {
			changed = true
			if err := os.Rename(root, filepath.Join(t.TempDir(), "retired")); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			write(root, "one", "two", "new-only")
		}
		return nil
	})
	finish := func() {
		t.Helper()
		for n := 0; n < 20; n++ {
			g.fileEventLoop()
			if g.virusRecovery == nil {
				return
			}
		}
		t.Fatal("recovery failed to finish")
	}
	status := func() (string, int64) {
		t.Helper()
		var s struct {
			Recovering bool   `json:"recovering"`
			Issue      string `json:"recovery_issue"`
			LastSweep  int64  `json:"last_sweep_at"`
		}
		if err := json.Unmarshal([]byte(g.FileWatchStatus()), &s); err != nil || s.Recovering || s.LastSweep == 0 {
			t.Fatalf("invalid completed recovery status: %+v err=%v", s, err)
		}
		return s.Issue, s.LastSweep
	}
	finish()
	count := func(dir string) int {
		n := 0
		for _, p := range checks {
			if filewatch.Within(p, dir) {
				n++
			}
		}
		return n
	}
	issue, last := status()
	if issue != "path_changed" || count(root) != 1 || count(other) != 2 {
		t.Fatalf("directory gap did not reach heartbeat or blocked later roots: issue=%q checks=%v", issue, checks)
	}
	// The normal periodic tick requests a new sweep, rather than resuming the
	// retired cursor or immediately looping on a continuously changing tree.
	checks = nil
	g.virusRescan = true
	finish()
	if issue, now := status(); issue != "" || now < last || count(root) != 3 || count(other) != 2 {
		t.Fatalf("fresh sweep did not recover coverage: issue=%q checks=%v", issue, checks)
	}
}

func TestRecoveryPublishesGapUntilCompletedCleanSweep(t *testing.T) {
	root, other := t.TempDir(), t.TempDir()
	write := func(dir string, count int) {
		t.Helper()
		for n := 0; n < count; n++ {
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprint(n)), []byte("harmless recovery status fixture"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	write(root, 2)
	write(other, 24)
	disabled := false
	g := New(&config.DecoyConfig{Enabled: &disabled}, nil, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	defer func() {
		if g.virusRecovery != nil {
			g.virusRecovery.Close()
		}
	}()
	g.SetVirusRoots([]string{root, other}, nil)
	// Heartbeats read coverage while the dispatcher advances recovery.
	stopHeartbeat, heartbeatDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		for {
			select {
			case <-stopHeartbeat:
				return
			default:
				_ = g.FileWatchStatus()
				runtime.Gosched()
			}
		}
	}()
	defer func() { close(stopHeartbeat); <-heartbeatDone }()
	changed := false
	g.SetVirusEngine(func(p string) *pb.VirusFinding {
		if !changed && filewatch.Within(p, root) {
			changed = true
			if err := os.Rename(root, filepath.Join(t.TempDir(), "retired")); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			write(root, 16)
		}
		return nil
	})
	status := func(recovering bool, issue string) int64 {
		t.Helper()
		var s struct {
			Recovering bool   `json:"recovering"`
			Issue      string `json:"recovery_issue"`
			LastSweep  int64  `json:"last_sweep_at"`
		}
		if err := json.Unmarshal([]byte(g.FileWatchStatus()), &s); err != nil {
			t.Fatal(err)
		}
		if s.Recovering != recovering || s.Issue != issue {
			t.Errorf("known recovery gap hidden before a completed clean sweep: got=%+v want recovering=%v issue=%q", s, recovering, issue)
		}
		return s.LastSweep
	}
	finish := func() {
		t.Helper()
		for n := 0; n < 30 && g.virusRecovery != nil; n++ {
			g.fileEventLoop()
		}
		if g.virusRecovery != nil {
			t.Fatal("recovery stopped making progress")
		}
	}
	// The remaining root deliberately spans several bounded batches.
	g.fileEventLoop()
	if g.virusRecovery == nil || !changed {
		t.Fatal("fixture did not retain traversal after the directory replacement")
	}
	if last := status(true, "path_changed"); last != 0 {
		t.Fatal("incomplete sweep advanced completion timestamp")
	}
	finish()
	last := status(false, "path_changed")
	if last == 0 {
		t.Fatal("completed sweep did not report its timestamp")
	}
	g.virusRescan = true // the existing periodic tick, without an eager retry
	g.fileEventLoop()
	if g.virusRecovery == nil {
		t.Fatal("fixture did not retain the fresh sweep")
	}
	if now := status(true, "path_changed"); now != last {
		t.Fatal("unfinished retry advanced completion timestamp")
	}
	finish()
	if now := status(false, ""); now < last {
		t.Fatal("completed clean sweep moved completion time backwards")
	}
}
