// Package systemacceptance checks real OS interfaces using production collectors.
package systemacceptance

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/collector"
	"github.com/alinksec/alinksec-agent/internal/filewatch"
	"github.com/alinksec/alinksec-agent/internal/identity"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/securestate"
)

func TestActualSystemInterfaces(t *testing.T) {
	output := os.Getenv("ALINKSEC_SYSTEM_EVIDENCE_FILE")
	if output == "" {
		t.Skip("explicit disposable system acceptance fixture")
	}
	if os.Getenv("ALINKSEC_SMOKE_ALLOW_FIXTURES") != "true" {
		t.Fatal("fixture authorization missing")
	}
	started := time.Now()
	host := identity.HostInfo()
	if host.Kernel == "" || host.Arch != runtime.GOARCH || host.OsVersion == "" {
		t.Fatalf("actual host identity unavailable: %q/%q", host.Kernel, host.OsVersion)
	}
	snapshot := collector.Snapshot([]string{"software", "disks"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	inv := snapshot.GetSoftwareInventory()
	if inv.GetStatus() != pb.SoftwareInventory_COMPLETE || len(snapshot.Software) == 0 {
		t.Fatalf("actual installed software inventory: %+v packages=%d", inv, len(snapshot.Software))
	}
	missingVersions := 0
	for _, item := range snapshot.Software {
		if item.Name == "" || item.Source == "" {
			t.Fatal("incomplete package identity")
		}
		if item.Version == "" {
			// Windows uninstall registry entries can legitimately omit
			// DisplayVersion. Preserve absence instead of inventing a version.
			if runtime.GOOS != "windows" || item.Source != "registry" {
				t.Fatal("native package manager omitted a version")
			}
			missingVersions++
		}
	}
	if missingVersions == len(snapshot.Software) {
		t.Fatal("no actual software versions observed")
	}
	root := filepath.Join(t.TempDir(), "系统适配 with spaces")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "state.json")
	if err := securestate.WriteJSON(state, map[string]string{"text": "中文原文"}); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]string
	if err := securestate.ReadJSON(state, &decoded); err != nil || decoded["text"] != "中文原文" {
		t.Fatal("private UTF-8 journal", err)
	}
	m := filewatch.New()
	m.Update([]filewatch.Root{{Path: root, Recursive: true}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); m.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("native watcher did not stop")
		}
	})
	wait := func(label string, condition func() bool) {
		t.Helper()
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			if condition() {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("%s: %+v", label, m.Status())
	}
	wait("native watcher registration", func() bool { return m.Status().Watches > 0 && m.Status().State == "watching" })
	m.Drain(filewatch.MaxPending)
	path := filepath.Join(root, "实际文件.txt")
	if err := os.WriteFile(path, []byte("harmless"), 0600); err != nil {
		t.Fatal(err)
	}
	wait("actual native event", func() bool {
		for _, p := range m.Drain(filewatch.MaxPending).Paths {
			if p == path {
				return true
			}
		}
		return false
	})
	if err := os.Rename(path, path+".renamed"); err != nil {
		t.Fatal(err)
	}
	wait("actual native rename", func() bool {
		for _, p := range m.Drain(filewatch.MaxPending).Paths {
			if p == path || p == path+".renamed" {
				return true
			}
		}
		return false
	})
	result := map[string]any{"passed": true, "head": os.Getenv("GITHUB_SHA"), "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH,
		"osVersion": host.OsVersion, "kernel": host.Kernel, "scope": os.Getenv("ALINKSEC_SYSTEM_SCOPE"), "image": os.Getenv("ALINKSEC_SYSTEM_IMAGE"),
		"packageCount": len(snapshot.Software), "missingVersionCount": missingVersions, "inventory": inv, "watcher": m.Status(), "elapsedMillis": time.Since(started).Milliseconds(),
		"checks": []string{"actual_os_identity", "actual_installed_software_complete", "package_identity_and_version_availability", "private_unicode_journal", "actual_native_file_event", "actual_native_rename", "bounded_watcher_shutdown"}}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("watcher shutdown")
	}
	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(output), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, b, 0600); err != nil {
		t.Fatal(err)
	}
}
