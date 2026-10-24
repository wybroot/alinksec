//go:build windows

package filetrace

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func nativePathName(t *testing.T, path string, short bool) string {
	t.Helper()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]uint16, 32768)
	var n uint32
	if short {
		n, err = windows.GetShortPathName(p, &b[0], uint32(len(b)))
	} else {
		n, err = windows.GetLongPathName(p, &b[0], uint32(len(b)))
	}
	if err != nil || n == 0 || n >= uint32(len(b)) {
		t.Fatalf("native path name: %d %v", n, err)
	}
	return windows.UTF16ToString(b[:n])
}

func TestShortPathAliasesPreserveEvidenceAndRootBoundary(t *testing.T) {
	root := nativePathName(t, t.TempDir(), false)
	alias := nativePathName(t, root, true)
	if !strings.Contains(alias, "~") {
		// Some volumes disable automatic creation. Only this disposable directory
		// is changed; never enable 8.3 names globally on the runner.
		_, _ = exec.Command("fsutil", "file", "setshortname", root, "ALINK~26").CombinedOutput()
		alias = nativePathName(t, root, true)
	}
	if !strings.Contains(alias, "~") {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatal("native 8.3 alias fixture was not created")
		}
		t.Skip("filesystem does not support a disposable short-name fixture")
	}
	leaf := "中文文件 with spaces.txt"
	path := filepath.Join(root, leaf)
	if err := os.WriteFile(path, []byte("harmless"), 0600); err != nil {
		t.Fatal(err)
	}
	short := filepath.Join(alias, leaf)
	if matchPath(short) != cleanPath(path) {
		t.Fatalf("alias mismatch: %q => %q, want %q", short, matchPath(short), path)
	}
	m := readyMonitor()
	m.Configure([]string{root}, 10*time.Second)
	if !m.watched(short) || m.watched(alias+" sibling\\"+leaf) {
		t.Fatal("alias widened policy root")
	}
	m.status = "ready"
	since := time.Now()
	id := Identity{PID: 100, Created: 500, Image: `C:\writer.exe`}
	m.observe(Write{Path: short, At: time.Now(), Process: id, Operation: "rename"})
	if err := os.Rename(path, path+".renamed"); err != nil {
		t.Fatal(err)
	}
	for _, missing := range []string{path, short} {
		if r := m.Lookup([]string{missing}, since); r.Status != "attributed" || r.Process == nil || *r.Process != id {
			t.Fatalf("missing-leaf alias: %+v", r)
		}
	}
	m.Configure([]string{alias}, 10*time.Second)
	if !m.watched(path + ".renamed") {
		t.Fatal("short policy root does not match long event path")
	}
	t.Logf("actual alias %q, long root %q, UTF-16 leaf, missing leaf and root boundary validated", alias, root)
}

func TestShortNameExpansionDoesNotResolveSymlinkTarget(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "protected")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "outside~link")
	if err := os.Symlink(target, link); err != nil {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatal(err)
		}
		t.Skip(err)
	}
	m := readyMonitor()
	m.Configure([]string{target}, 10*time.Second)
	if m.watched(filepath.Join(link, "missing.txt")) {
		t.Fatal("short-name matching followed a link into a watched root")
	}
}
