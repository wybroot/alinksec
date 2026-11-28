//go:build windows

package virusscan

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

func openDirectory(path string) (*os.File, error) {
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	p, err := windows.UTF16PtrFromString(canonical)
	if err != nil {
		return nil, err
	}
	// A pinned reader must survive an atomic signature-directory switch. Keep
	// its identity while allowing the old directory to be renamed for retirement.
	h, err := windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: canonical, Err: err}
	}
	f := os.NewFile(uintptr(h), canonical)
	st, err := f.Stat()
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		f.Close()
		return nil, fmt.Errorf("not a regular directory: %s", canonical)
	}
	return f, nil
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
		// Preserve Go's filesystem error classification (notably optional rules.json).
		if status, ok := err.(windows.NTStatus); ok {
			err = status.Errno()
		}
		return nil, &os.PathError{Op: "open", Path: filepath.Join(parent.Name(), name), Err: err}
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
const (
	fileDispositionInfoEx         = 21
	fileDispositionDelete         = 0x00000001
	fileDispositionPosixSemantics = 0x00000002
)

func syncDir(dir *os.File) error { return nil }

func isCrossDeviceErr(err error) bool {
	var nt windows.NTStatus
	if errors.As(err, &nt) && nt == windows.STATUS_NOT_SAME_DEVICE {
		return true
	}
	return errors.Is(err, windows.ERROR_NOT_SAME_DEVICE) || errors.Is(err, syscall.EXDEV)
}

func isRestoreConflictErr(err error) bool {
	var nt windows.NTStatus
	if errors.As(err, &nt) && (nt == windows.STATUS_OBJECT_NAME_COLLISION || nt == windows.STATUS_OBJECT_NAME_EXISTS) {
		return true
	}
	return errors.Is(err, os.ErrExist) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_FILE_EXISTS)
}

func isFileInUseErr(err error) bool {
	var nt windows.NTStatus
	if errors.As(err, &nt) {
		switch nt {
		case windows.STATUS_SHARING_VIOLATION, windows.STATUS_FILE_LOCK_CONFLICT, windows.STATUS_CANNOT_DELETE, windows.STATUS_DELETE_PENDING:
			return true
		}
	}
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}

func isDiskFullErr(err error) bool {
	var nt windows.NTStatus
	if errors.As(err, &nt) && nt == windows.STATUS_DISK_FULL {
		return true
	}
	return errors.Is(err, windows.ERROR_DISK_FULL) || errors.Is(err, windows.ERROR_HANDLE_DISK_FULL)
}

func deleteOpenHandle(file *os.File) error {
	flags := uint32(fileDispositionDelete | fileDispositionPosixSemantics)
	err := windows.SetFileInformationByHandle(windows.Handle(file.Fd()), fileDispositionInfoEx, (*byte)(unsafe.Pointer(&flags)), uint32(unsafe.Sizeof(flags)))
	if err != nil && (errors.Is(err, windows.ERROR_INVALID_FUNCTION) || errors.Is(err, windows.ERROR_NOT_SUPPORTED) || errors.Is(err, windows.ERROR_INVALID_PARAMETER)) {
		one := byte(1)
		err = windows.SetFileInformationByHandle(windows.Handle(file.Fd()), windows.FileDispositionInfo, &one, 1)
	}
	return err
}

func removeCrossVolumeSource(ctx context.Context, parent, file *os.File, base string, origInfo os.FileInfo, expected string, onStage func(stageDir string) error) (bool, error) {
	current, err := statAt(parent, base)
	if err != nil || !os.SameFile(origInfo, current) {
		return false, fmt.Errorf("%w: original path replaced before isolation", errTargetChanged)
	}
	got, err := openedDigest(ctx, file)
	if err != nil || got != expected {
		return false, fmt.Errorf("%w: target modified before isolation", errTargetChanged)
	}
	if err := deleteOpenHandle(file); err != nil {
		if isFileInUseErr(err) || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return false, fmt.Errorf("%w: %v", errFileInUse, err)
		}
		return false, err
	}
	// Closing the pinned handle completes NTFS unlink immediately under POSIX semantics.
	_ = file.Close()
	return false, nil
}

func reconcileStageDir(ctx context.Context, parent *os.File, base, stageName, expected string) (stageOutcome, error) {
	return stageAbsent, nil
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
		if isDiskFullErr(err) {
			return fmt.Errorf("%w: %v", errInsufficientSpace, err)
		}
		return err
	}
	defer out.Close()
	defer removeAt(parent, temp)
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := copyBounded(ctx, out, src, maxFileSize); err != nil {
		if isDiskFullErr(err) {
			return fmt.Errorf("%w: %v", errInsufficientSpace, err)
		}
		return err
	}
	if err := out.Sync(); err != nil {
		if isDiskFullErr(err) {
			return fmt.Errorf("%w: %v", errInsufficientSpace, err)
		}
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
	if err := renamePinned(parent, out, temp, parent, name); err != nil {
		if isRestoreConflictErr(err) {
			return fmt.Errorf("%w: %v", errRestoreConflict, err)
		}
		return err
	}
	return nil
}
