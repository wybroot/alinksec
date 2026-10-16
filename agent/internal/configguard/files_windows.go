//go:build windows

package configguard

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func isLink(i os.FileInfo) bool {
	s, ok := i.Sys().(*syscall.Win32FileAttributeData)
	return i.Mode()&os.ModeSymlink != 0 || ok && s.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}
func openNoFollow(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	var i windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &i); err != nil || i.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || i.NumberOfLinks != 1 {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("configuration reparse point or invalid handle")
	}
	return os.NewFile(uintptr(h), path), nil
}
func privateFile(path string) error {
	i, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !i.Mode().IsRegular() || isLink(i) {
		return fmt.Errorf("configuration record is not regular")
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 {
		return fmt.Errorf("configuration DACL unavailable")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || (!owner.IsWellKnown(windows.WinLocalSystemSid) && !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !owner.Equals(user.User.Sid)) {
		return fmt.Errorf("configuration owner is untrusted")
	}
	for n := uint32(0); n < uint32(dacl.AceCount); n++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, n, &ace); err != nil {
			return err
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("unsupported configuration ACE")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsWellKnown(windows.WinLocalSystemSid) && !sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !sid.Equals(user.User.Sid) {
			return fmt.Errorf("configuration DACL permits an untrusted principal")
		}
	}
	return nil
}
func protectFile(path string) error {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	owner, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, dacl, nil)
}
func writableParent(path string) error {
	// The store's parent is protected by securestate.PrivateDir; source shadows
	// may live in a separately managed admin directory (including read-only mounts).
	i, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !i.IsDir() || isLink(i) {
		return fmt.Errorf("configuration parent is not a real directory")
	}
	return nil
}
