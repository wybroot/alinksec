//go:build windows

package virusscan

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"unsafe"
)

func openDirectory(path string) (*os.File, error) {
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	return os.Open(canonical)
}
func openRegular(path string, mutation bool) (*os.File, *os.File, error) {
	parent, err := openDirectory(filepath.Dir(path))
	if err != nil {
		return nil, nil, err
	}
	f, err := openAtAccess(parent, filepath.Base(path), false, mutation)
	if err != nil {
		parent.Close()
		return nil, nil, err
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 {
		f.Close()
		parent.Close()
		return nil, nil, fmt.Errorf("not a regular file")
	}
	return f, parent, nil
}
func openAt(parent *os.File, name string, create bool) (*os.File, error) {
	return openAtAccess(parent, name, create, false)
}
func openMutatingAt(parent *os.File, name string) (*os.File, error) {
	return openAtAccess(parent, name, false, true)
}
func openAtAccess(parent *os.File, name string, create, mutation bool) (*os.File, error) {
	object, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, err
	}
	attrs := &windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: windows.Handle(parent.Fd()), ObjectName: object, Attributes: windows.OBJ_CASE_INSENSITIVE}
	access := uint32(windows.FILE_GENERIC_READ)
	if mutation || create {
		access |= windows.DELETE
	}
	disposition := uint32(windows.FILE_OPEN)
	if create {
		access |= windows.FILE_GENERIC_WRITE | windows.WRITE_DAC | windows.WRITE_OWNER
		disposition = windows.FILE_CREATE
	}
	var h windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	// Deny shared writes while the descriptor is held; reparse points are opened
	// themselves and rejected, never resolved to a target file.
	err = windows.NtCreateFile(&h, access, attrs, &iosb, nil, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE, disposition, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), filepath.Join(parent.Name(), name)), nil
}
func statAt(parent *os.File, name string) (os.FileInfo, error) {
	f, err := openAt(parent, name, false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Stat()
}
func renamePinned(from *os.File, file *os.File, name string, to *os.File, newName string) error {
	type renameInfo struct {
		Replace byte
		Root    windows.Handle
		Length  uint32
		Name    [1]uint16
	}
	utf, err := windows.UTF16FromString(newName)
	if err != nil {
		return err
	}
	n := len(utf) - 1
	data := make([]byte, int(unsafe.Offsetof(renameInfo{}.Name))+n*2)
	info := (*renameInfo)(unsafe.Pointer(&data[0]))
	info.Root = windows.Handle(to.Fd())
	info.Length = uint32(n * 2)
	copy(unsafe.Slice(&info.Name[0], n), utf[:n])
	var iosb windows.IO_STATUS_BLOCK
	return windows.NtSetInformationFile(windows.Handle(file.Fd()), &iosb, &data[0], uint32(len(data)), windows.FileRenameInformation)
}
func removeAt(parent *os.File, name string) error {
	f, err := openMutatingAt(parent, name)
	if err != nil {
		return err
	}
	defer f.Close()
	value := byte(1)
	return windows.SetFileInformationByHandle(windows.Handle(f.Fd()), windows.FileDispositionInfo, &value, 1)
}
func parentIdentity(parent *os.File) string {
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(windows.Handle(parent.Fd()), &info) != nil {
		return ""
	}
	return fmt.Sprintf("%d:%d:%d", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow)
}
func originalOwner(info os.FileInfo) (int, int) { return -1, -1 }

// Go's Unix mode bits do not restrict a Windows directory. Protect the dedicated
// Agent state with an inheritable DACL and reject reparse points/untrusted owners.
func secureAgentState(paths ...string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sid := user.User.Sid.String()
	private, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + sid + ")")
	if err != nil {
		return err
	}
	dacl, _, err := private.DACL()
	if err != nil {
		return err
	}
	for _, path := range paths {
		st, err := os.Lstat(path)
		if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("unsafe Agent state directory")
		}
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
		if err != nil {
			return err
		}
		owner, _, err := sd.Owner()
		if err != nil {
			return err
		}
		ownerID := owner.String()
		if ownerID != sid && ownerID != "S-1-5-18" && ownerID != "S-1-5-32-544" {
			return fmt.Errorf("untrusted Agent state owner")
		}
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
			return err
		}
	}
	return nil
}
func originalSecurity(file *os.File) (string, error) {
	sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return "", err
	}
	return sd.String(), nil
}
func restoreCopy(ctx context.Context, src *os.File, parent *os.File, name string, mode os.FileMode, uid, gid int, security string) error {
	temp := ".alinksec-restore-" + randomID()
	out, err := openAt(parent, temp, true)
	if err != nil {
		return err
	}
	defer out.Close()
	defer removeAt(parent, temp)
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := copyBounded(ctx, out, src, maxFileSize); err != nil {
		return err
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if security == "" {
		return fmt.Errorf("original Windows permissions unavailable")
	}
	sd, err := windows.SecurityDescriptorFromString(security)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	group, _, err := sd.Group()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetSecurityInfo(windows.Handle(out.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, group, dacl, nil); err != nil {
		return err
	}
	return renamePinned(parent, out, temp, parent, name)
}
