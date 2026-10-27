//go:build linux || windows

package guard

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/config"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func TestRecoveryYieldsToNativeEventAndResumes(t *testing.T) {
	root := t.TempDir()
	files := make(map[string]bool)
	for n := 0; n < 20; n++ {
		p := filepath.Join(root, fmt.Sprintf("existing-%02d", n))
		if err := os.WriteFile(p, []byte("harmless existing content"), 0600); err != nil {
			t.Fatal(err)
		}
		files[p] = false
	}
	disabled := false
	g := New(&config.DecoyConfig{Enabled: &disabled}, nil, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	g.SetVirusRoots([]string{root}, nil)
	var order []string
	event := filepath.Join(root, "new-event")
	g.SetVirusEngine(func(p string) *pb.VirusFinding {
		order = append(order, p)
		if _, ok := files[p]; ok {
			files[p] = true
		}
		if len(order) == 1 {
			// Deliver a real OS event while the first recovery check is running.
			if err := os.WriteFile(event, []byte("harmless new content"), 0600); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(5 * time.Second)
			for g.watcher.Status().Pending == 0 {
				if time.Now().After(deadline) {
					t.Fatal("native event was not collected")
				}
				time.Sleep(time.Millisecond)
			}
		}
		return nil
	})
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
	deadline := time.Now().Add(5 * time.Second)
	for g.watcher.Status().Watches < 2 {
		if time.Now().After(deadline) {
			t.Fatal("native watcher was not registered", g.FileWatchStatus())
		}
		time.Sleep(time.Millisecond)
	}
	g.fileEventLoop()
	if len(order) != 1 || g.virusRecovery == nil {
		t.Fatalf("recovery continued ahead of the queued event: checks=%d recovery=%v", len(order), g.virusRecovery != nil)
	}
	g.fileEventLoop()
	if len(order) < 2 || order[1] != event {
		t.Fatalf("next dispatch did not prioritize native event: %v", order)
	}
	for n := 0; g.virusRecovery != nil && n < 30; n++ {
		g.fileEventLoop()
	}
	if g.virusRecovery != nil {
		t.Fatal("yielded recovery did not finish")
	}
	for p, seen := range files {
		if !seen {
			t.Fatal("yield lost a recovery file", p)
		}
	}
	t.Log("real native event dispatched immediately after the in-flight recovery file; all 20 existing files subsequently checked")
}

func TestRecoveryRetainsProgressWithPendingEvents(t *testing.T) {
	root := t.TempDir()
	var paths []string
	for n := 0; n < 40; n++ {
		p := filepath.Join(root, fmt.Sprintf("event-%02d", n))
		if err := os.WriteFile(p, nil, 0600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	disabled := false
	g := New(&config.DecoyConfig{Enabled: &disabled}, nil, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	defer func() {
		if g.virusRecovery != nil {
			g.virusRecovery.Close()
		}
	}()
	g.SetVirusRoots([]string{root}, nil)
	var checks []string
	g.SetVirusEngine(func(p string) *pb.VirusFinding { checks = append(checks, p); return nil })
	g.eventPending = append([]string(nil), paths...)
	g.fileEventLoop()
	if len(checks) != 33 || len(g.eventPending) != 8 || g.virusRecovery == nil {
		t.Fatalf("expected 32 events plus one recovery file, retaining eight events: checks=%d pending=%d recovery=%v", len(checks), len(g.eventPending), g.virusRecovery != nil)
	}
	g.fileEventLoop()
	if len(g.eventPending) != 0 {
		t.Fatal("retained event backlog did not drain")
	}
	for i, p := range paths[32:] {
		if checks[33+i] != p {
			t.Fatal("retained event lost priority", checks[33:])
		}
	}
	for n := 0; g.virusRecovery != nil && n < 40; n++ {
		g.fileEventLoop()
	}
	if g.virusRecovery != nil {
		t.Fatal("recovery failed to resume after event backlog drained")
	}
	seen := map[string]int{}
	for _, p := range checks {
		seen[p]++
	}
	for _, p := range paths {
		if seen[p] != 2 {
			t.Fatalf("expected one event and one recovery check for %s, got %d", p, seen[p])
		}
	}
	t.Log("retained event backlog keeps priority while recovery still advances one file, then resumes without loss")
}
