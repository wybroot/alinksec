package scap

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestNativeWorkspaceExpandsDOSAlias(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Private Native Workspace")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, 32768)
	n, err := windows.GetShortPathName(name, &buffer[0], uint32(len(buffer)))
	if err != nil || n == 0 || n >= uint32(len(buffer)) {
		t.Fatal("OS short path lookup failed", err)
	}
	long, err := nativeWorkspacePath(windows.UTF16ToString(buffer[:n]))
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.Stat(long)
	if err != nil || !os.SameFile(want, got) || filepath.Base(long) != "Private Native Workspace" {
		t.Fatal("native workspace changed identity or retained DOS alias", long, err)
	}
}
