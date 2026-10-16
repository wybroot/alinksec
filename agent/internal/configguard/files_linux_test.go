//go:build linux

package configguard

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestFIFOAndHardlinkCannotRedirectConfigurationReadsOrRepairs(t *testing.T) {
	for _, kind := range []string{"fifo", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			s, _, path, _ := testStore(t)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "unrelated")
			const sentinel = "unrelated content must survive"
			if err := os.WriteFile(target, []byte(sentinel), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			if kind == "fifo" {
				err = unix.Mkfifo(path, 0600)
			} else {
				err = os.Link(target, path)
			}
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			if err := s.Check(); err != nil {
				t.Fatal(err)
			}
			if time.Since(start) > time.Second {
				t.Fatal("special file blocked integrity check")
			}
			if b, _ := os.ReadFile(target); string(b) != sentinel {
				t.Fatal("repair changed unrelated hardlink target")
			}
			if kind == "fifo" && s.Events()[0].Shadow != "blocked" {
				t.Fatal("FIFO was reported as restored")
			}
		})
	}
}

func TestBlockedExternalShadowKeepsPinnedConfigurationAcrossRestart(t *testing.T) {
	work := t.TempDir()
	external := t.TempDir()
	path := filepath.Join(external, "agent.yml")
	good := []byte("server_addr: trusted.example:9443\n")
	if err := os.WriteFile(path, good, 0600); err != nil {
		t.Fatal(err)
	}
	s, _, err := Open(work, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := os.WriteFile(path, []byte("server_addr: hostile.example:9443\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(external, 0777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(external, 0700) })
	if err := s.Check(); err != nil {
		t.Fatal(err)
	}
	if events := s.Events(); len(events) != 1 || events[0].Shadow != "blocked" {
		t.Fatalf("blocked shadow was misreported: %+v", events)
	}
	s.Close()
	next, cfg, err := Open(work, path)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if cfg.ServerAddr != "trusted.example:9443" || !bytes.Equal(next.r.Agent, good) {
		t.Fatal("unrepaired shadow replaced pinned configuration on restart")
	}
}
