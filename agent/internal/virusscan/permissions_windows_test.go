//go:build windows

package virusscan

import (
	"context"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsQuarantineUsesProtectedDACLAndRestoresOriginalSecurity(t *testing.T) {
	work := t.TempDir()
	path, hash := harmlessSample(t, "Windows harmless ACL fixture")
	before, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	q := NewQuarantine(work)
	id, err := q.QuarantineExpected(context.Background(), path, hash)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{work, q.dir, filepath.Join(q.dir, id+".payload")} {
		sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		sddl := sd.String()
		if (p != filepath.Join(q.dir, id+".payload") && !strings.Contains(sddl, "D:P")) || strings.Contains(sddl, ";;;WD)") || strings.Contains(sddl, ";;;BU)") {
			t.Fatal("quarantine is accessible to ordinary users", sddl)
		}
	}
	if err = q.RestoreExpected(context.Background(), path, id, hash); err != nil {
		t.Fatal(err)
	}
	after, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	oldOwner, _, _ := before.Owner()
	newOwner, _, _ := after.Owner()
	if oldOwner.String() != newOwner.String() {
		t.Fatal("original owner not restored")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "Windows harmless ACL fixture" {
		t.Fatal("restore changed bytes", err)
	}
}
