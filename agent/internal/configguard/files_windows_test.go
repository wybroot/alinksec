//go:build windows

package configguard

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsRecordOwnerAndShadowDACLRecovery(t *testing.T) {
	s, _, path, _ := testStore(t)
	sd, err := windows.GetNamedSecurityInfo(s.recordPath(), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil || !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		t.Fatal("trusted record owner does not support installer-to-SYSTEM handoff")
	}
	unsafeSD, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := unsafeSD.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Check(); err != nil {
		t.Fatal(err)
	}
	if err := privateFile(path); err != nil {
		t.Fatal("shadow DACL was not restored: ", err)
	}
	if events := s.Events(); len(events) != 1 || events[0].Reason != "unsafe_permissions" || events[0].Shadow != "restored" {
		t.Fatalf("DACL drift was not reported truthfully: %+v", events)
	}
}

func TestWindowsRejectsDeviceUNCAndAlternateStreamConfiguration(t *testing.T) {
	for _, path := range []string{`\\server\share\agent.yml`, `\\?\C:\agent.yml`, `C:\agent.yml:hidden`} {
		if _, err := absolute(path); err == nil {
			t.Fatalf("accepted unsafe Windows path %q", path)
		}
	}
}
