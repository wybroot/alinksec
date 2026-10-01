package guard

import (
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/alinksec/alinksec-agent/internal/config"
)

func TestPolicyUpdatesWhileRateMonitoring(t *testing.T) {
	dir := t.TempDir()
	enabled := true
	policy := func() *config.DecoyConfig {
		cfg := &config.DecoyConfig{Enabled: &enabled, Dirs: []string{dir}, WatchTrees: []string{dir},
			CountPerDir: 1, RateThreshold: 1 << 30, Response: "alert_only"}
		cfg.Normalize()
		return cfg
	}
	g := New(policy(), nil, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		for range 50 {
			g.UpdatePolicy(policy(), nil)
		}
	}()
	go func() {
		defer workers.Done()
		for range 200 {
			g.rateLoop()
		}
	}()
	workers.Wait()
	if got := g.cur(); len(got.WatchTrees) != 1 || got.WatchTrees[0] != dir {
		t.Fatal("latest policy was not retained")
	}
}
