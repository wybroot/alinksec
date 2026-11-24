//go:build linux

package virusscan

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func openDirectory(path string) (*os.File, error) {
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open(canonical, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), canonical), nil
}
func openRegular(path string, mutation bool) (*os.File, *os.File, error) {
	parent, err := openDirectory(filepath.Dir(path))
	if err != nil {
		return nil, nil, err
	}
	f, err := openAt(parent, filepath.Base(path), false)
	if err != nil {
		parent.Close()
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		parent.Close()
		return nil, nil, fmt.Errorf("not a regular file")
	}
	return f, parent, nil
}
func openAt(parent *os.File, name string, create bool) (*os.File, error) {
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	if create {
		flags = unix.O_RDWR | unix.O_CREAT | unix.O_EXCL | unix.O_NOFOLLOW | unix.O_CLOEXEC
	}
	fd, err := unix.Openat(int(parent.Fd()), name, flags, 0600)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), filepath.Join(parent.Name(), name)), nil
}
func statAt(parent *os.File, name string) (os.FileInfo, error) {
	f, err := openAt(parent, name, false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Stat()
}
func openMutatingAt(parent *os.File, name string) (*os.File, error) {
	return openAt(parent, name, false)
}
func renamePinned(from *os.File, file *os.File, name string, to *os.File, newName string) error {
	if err := unix.Renameat2(int(from.Fd()), name, int(to.Fd()), newName, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	before, err := file.Stat()
	after, aerr := statAt(to, newName)
	if err != nil || aerr != nil || !os.SameFile(before, after) {
		return fmt.Errorf("moved file identity changed")
	}
	return nil
}
func removeAt(parent *os.File, name string) error { return unix.Unlinkat(int(parent.Fd()), name, 0) }
func parentIdentity(parent *os.File) string {
	info, err := parent.Stat()
	if err != nil {
		return ""
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d:%d", s.Dev, s.Ino)
}
func originalOwner(info os.FileInfo) (int, int) {
	if s, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(s.Uid), int(s.Gid)
	}
	return -1, -1
}
func originalSecurity(file *os.File) (string, error) { return "", nil }
func secureAgentState(paths ...string) error         { return nil } // directory() checks UID and mode.

func syncDir(dir *os.File) error {
	if dir == nil {
		return nil
	}
	err := dir.Sync()
	if err == nil || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EROFS) || errors.Is(err, unix.EBADF) {
		return nil
	}
	return err
}

func isCrossDeviceErr(err error) bool {
	return errors.Is(err, unix.EXDEV) || errors.Is(err, syscall.EXDEV)
}

func isRestoreConflictErr(err error) bool {
	return errors.Is(err, os.ErrExist) || errors.Is(err, unix.EEXIST) || errors.Is(err, syscall.EEXIST)
}

func isFileInUseErr(err error) bool {
	return errors.Is(err, unix.ETXTBSY) || errors.Is(err, unix.EBUSY)
}

func isDiskFullErr(err error) bool {
	return errors.Is(err, unix.ENOSPC) || errors.Is(err, unix.EDQUOT) || errors.Is(err, syscall.ENOSPC)
}

func removeCrossVolumeSource(ctx context.Context, parent, file *os.File, base string, origInfo os.FileInfo, expected string, onStage func(stageDir string) error) (bool, error) {
	stageName := ".alinksec-quarantine-" + randomID()
	if err := unix.Mkdirat(int(parent.Fd()), stageName, 0700); err != nil {
		if isDiskFullErr(err) {
			return false, fmt.Errorf("%w: %v", errInsufficientSpace, err)
		}
		return false, err
	}
	sfd, err := unix.Openat(int(parent.Fd()), stageName, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Unlinkat(int(parent.Fd()), stageName, unix.AT_REMOVEDIR)
		return false, err
	}
	stageDir := os.NewFile(uintptr(sfd), filepath.Join(parent.Name(), stageName))
	if onStage != nil {
		if err := onStage(stageName); err != nil {
			_ = stageDir.Close()
			_ = unix.Unlinkat(int(parent.Fd()), stageName, unix.AT_REMOVEDIR)
			return false, err
		}
	}
	if err := unix.Renameat2(int(parent.Fd()), base, int(stageDir.Fd()), "victim", unix.RENAME_NOREPLACE); err != nil {
		_ = stageDir.Close()
		_ = unix.Unlinkat(int(parent.Fd()), stageName, unix.AT_REMOVEDIR)
		if isFileInUseErr(err) {
			return false, fmt.Errorf("%w: %v", errFileInUse, err)
		}
		return false, err
	}
	movedInfo, err := statAt(stageDir, "victim")
	if err != nil || !os.SameFile(origInfo, movedInfo) {
		rbErr := unix.Renameat2(int(stageDir.Fd()), "victim", int(parent.Fd()), base, unix.RENAME_NOREPLACE)
		_ = stageDir.Close()
		if rbErr == nil {
			_ = unix.Unlinkat(int(parent.Fd()), stageName, unix.AT_REMOVEDIR)
			return false, fmt.Errorf("%w: original path replaced before isolation", errTargetChanged)
		}
		// Never unlink an unverified file when rollback hits a collision.
		return true, fmt.Errorf("%w: replacement rollback conflict: %v", errQuarantineIncomplete, rbErr)
	}
	got, err := openedDigest(ctx, file)
	if err != nil || got != expected {
		rbErr := unix.Renameat2(int(stageDir.Fd()), "victim", int(parent.Fd()), base, unix.RENAME_NOREPLACE)
		_ = stageDir.Close()
		if rbErr == nil {
			_ = unix.Unlinkat(int(parent.Fd()), stageName, unix.AT_REMOVEDIR)
			return false, fmt.Errorf("%w: target modified before isolation", errTargetChanged)
		}
		return true, fmt.Errorf("%w: modified source rollback conflict: %v", errQuarantineIncomplete, rbErr)
	}
	uErr := unix.Unlinkat(int(stageDir.Fd()), "victim", 0)
	_ = stageDir.Close()
	if uErr != nil {
		return true, fmt.Errorf("%w: staged unlink failed: %v", errQuarantineIncomplete, uErr)
	}
	_ = unix.Unlinkat(int(parent.Fd()), stageName, unix.AT_REMOVEDIR)
	_ = syncDir(parent)
	return false, nil
}

func reconcileStageDir(ctx context.Context, parent *os.File, base, stageName, expected string) (stageOutcome, error) {
	if !stageDirPattern.MatchString(stageName) {
		return stageRollbackConflict, fmt.Errorf("invalid stage directory name")
	}
	sfd, err := unix.Openat(int(parent.Fd()), stageName, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || os.IsNotExist(err) {
			return stageAbsent, nil
		}
		return stageRollbackConflict, err
	}
	stageDir := os.NewFile(uintptr(sfd), filepath.Join(parent.Name(), stageName))
	vf, err := openAt(stageDir, "victim", false)
	if err != nil {
		_ = stageDir.Close()
		if os.IsNotExist(err) {
			_ = unix.Unlinkat(int(parent.Fd()), stageName, unix.AT_REMOVEDIR)
			return stageCleanedEmpty, nil
		}
		return stageRollbackConflict, err
	}
	if expected != "" {
		got, derr := openedDigest(ctx, vf)
		_ = vf.Close()
		if derr == nil && got == expected {
			if uErr := unix.Unlinkat(int(stageDir.Fd()), "victim", 0); uErr != nil {
				_ = stageDir.Close()
				return stageRollbackConflict, uErr
			}
			_ = stageDir.Close()
			_ = unix.Unlinkat(int(parent.Fd()), stageName, unix.AT_REMOVEDIR)
			_ = syncDir(parent)
			return stageCompletedUnlink, nil
		}
	} else {
		_ = vf.Close()
	}
	rbErr := unix.Renameat2(int(stageDir.Fd()), "victim", int(parent.Fd()), base, unix.RENAME_NOREPLACE)
	_ = stageDir.Close()
	if rbErr == nil {
		_ = unix.Unlinkat(int(parent.Fd()), stageName, unix.AT_REMOVEDIR)
		_ = syncDir(parent)
		return stageRolledBackSource, nil
	}
	return stageRollbackConflict, nil
}

func restoreCopy(ctx context.Context, src *os.File, parent *os.File, name string, mode os.FileMode, uid, gid int, security string) error {
	stageName := ".alinksec-restore-" + randomID()
	if err := unix.Mkdirat(int(parent.Fd()), stageName, 0700); err != nil {
		if isDiskFullErr(err) {
			return fmt.Errorf("%w: %v", errInsufficientSpace, err)
		}
		return err
	}
	fd, err := unix.Openat(int(parent.Fd()), stageName, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Unlinkat(int(parent.Fd()), stageName, unix.AT_REMOVEDIR)
		return err
	}
	stage := os.NewFile(uintptr(fd), filepath.Join(parent.Name(), stageName))
	defer stage.Close()
	defer unix.Unlinkat(int(parent.Fd()), stageName, unix.AT_REMOVEDIR)
	out, err := openAt(stage, "payload", true)
	if err != nil {
		if isDiskFullErr(err) {
			return fmt.Errorf("%w: %v", errInsufficientSpace, err)
		}
		return err
	}
	defer out.Close()
	defer removeAt(stage, "payload")
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := copyBounded(ctx, out, src, maxFileSize); err != nil {
		if isDiskFullErr(err) {
			return fmt.Errorf("%w: %v", errInsufficientSpace, err)
		}
		return err
	}
	if uid >= 0 && gid >= 0 {
		if err := out.Chown(uid, gid); err != nil {
			return err
		}
	}
	if err := out.Chmod(mode.Perm()); err != nil {
		return err
	}
	if err := out.Sync(); err != nil {
		if isDiskFullErr(err) {
			return fmt.Errorf("%w: %v", errInsufficientSpace, err)
		}
		return err
	}
	// linkat never overwrites an existing file or dangling symlink. The source
	// inode stays inside an Agent-owned directory throughout publication.
	if err := unix.Linkat(int(stage.Fd()), "payload", int(parent.Fd()), name, 0); err != nil {
		if isRestoreConflictErr(err) {
			return fmt.Errorf("%w: %v", errRestoreConflict, err)
		}
		return err
	}
	_ = syncDir(parent)
	return nil
}
