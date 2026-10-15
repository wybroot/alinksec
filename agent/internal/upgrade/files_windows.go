//go:build windows

package upgrade

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

func protectDirectory(path string) error {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func lockUpgrade(workDir string) (func(), error) {
	if err := privateDir(upgradeDir(workDir)); err != nil {
		return nil, err
	}
	path := filepath.Join(upgradeDir(workDir), "lock")
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return nil, fmt.Errorf("invalid upgrade lock")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	var overlapped windows.Overlapped
	deadline := time.Now().Add(5 * time.Second)
	for {
		err = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped)
		if err == nil {
			return func() { windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &overlapped); f.Close() }, nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) || time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("upgrade transaction is locked: %w", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func replaceRecord(src, dst string) error {
	s, err := windows.UTF16PtrFromString(src)
	if err != nil {
		return err
	}
	d, err := windows.UTF16PtrFromString(dst)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(s, d, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func syncDirectory(string) error { return nil }
func moveExecutable(src, dst string) error {
	s, err := windows.UTF16PtrFromString(src)
	if err != nil {
		return err
	}
	d, err := windows.UTF16PtrFromString(dst)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(s, d, windows.MOVEFILE_WRITE_THROUGH)
}
