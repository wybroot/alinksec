//go:build windows

package comm

import (
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func assertEvidenceJournalPrivate(t *testing.T, path string) {
	t.Helper()
	// Windows privacy is enforced by the inherited DACL; POSIX mode bits do
	// not describe who can read this file on Windows.
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.KeepAlive(sd)
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 2 {
		t.Fatal("expiry lost private journal DACL", err)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || !sid.IsWellKnown(windows.WinLocalSystemSid) && !sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			t.Fatal("expired journal replacement grants access beyond SYSTEM and Administrators")
		}
	}
}
