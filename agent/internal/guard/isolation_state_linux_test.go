//go:build linux

package guard

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestFailedRestorePreservesIsolationMarker(t *testing.T) {
	workDir := t.TempDir()
	binDir := t.TempDir()
	t.Setenv("PATH", binDir)
	for _, executable := range []string{"iptables", "iptables-nft"} {
		if err := os.WriteFile(filepath.Join(binDir, executable), []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	marker := filepath.Join(workDir, "isolated.json")
	if err := os.WriteFile(marker, []byte(`{"reason":"fixture"}`), 0600); err != nil {
		t.Fatal(err)
	}
	g := &Guard{workDir: workDir, isolated: true, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := g.RestoreIsolation(); err == nil {
		t.Fatal("failed firewall restore returned success")
	}
	if !g.Isolated() {
		t.Fatal("failed restore cleared the isolation state")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("failed restore removed the restart marker: %v", err)
	}
}
