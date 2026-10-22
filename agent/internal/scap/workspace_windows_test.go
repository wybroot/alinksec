package scap

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestNativeWorkspaceStartsWithPrivateInheritableDACL(t *testing.T) {
	path, err := makeNativeWorkspace()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(path)
	file := filepath.Join(path, "native-module")
	if err := os.WriteFile(file, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{path, file} {
		sd, err := windows.GetNamedSecurityInfo(name, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := sd.DACL()
		if err != nil || dacl == nil || dacl.AceCount != 2 {
			t.Fatal("native workspace is not restricted to SYSTEM and administrators", err)
		}
		control, _, err := sd.Control()
		if err != nil || name == path && control&windows.SE_DACL_PROTECTED == 0 {
			t.Fatal("native workspace inherits its parent's DACL", err)
		}
		for i := uint32(0); i < uint32(dacl.AceCount); i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(dacl, i, &ace); err != nil {
				t.Fatal(err)
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || !sid.IsWellKnown(windows.WinLocalSystemSid) && !sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
				t.Fatal("untrusted principal can access native workspace")
			}
		}
	}
}

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
