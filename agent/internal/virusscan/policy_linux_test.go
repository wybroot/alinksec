//go:build linux

package virusscan

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPinnedEngineNeverOpensFIFOShadowDuringConstruction(t *testing.T) {
	work := t.TempDir()
	if err := unix.Mkfifo(filepath.Join(work, "policy.json"), 0600); err != nil {
		t.Fatal(err)
	}
	finished := make(chan *Engine, 1)
	go func() {
		finished <- NewEngineWithPolicyReader(work, slog.New(slog.NewTextHandler(io.Discard, nil)), func() ([]byte, error) {
			return []byte(`{"virus_realtime":{"enabled":true,"action":"quarantine"}}`), nil
		})
	}()
	select {
	case engine := <-finished:
		if enabled, quarantine := engine.RealtimePolicy(work); !enabled || !quarantine {
			t.Fatal("pinned periodic protection was not retained")
		}
	case <-time.After(time.Second):
		t.Fatal("engine construction opened the untrusted FIFO shadow")
	}
}
