//go:build linux

package virusscan

import (
	"context"
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
func restoreCopy(ctx context.Context, src *os.File, parent *os.File, name string, mode os.FileMode, uid, gid int, security string) error {
	stageName := ".alinksec-restore-" + randomID()
	if err := unix.Mkdirat(int(parent.Fd()), stageName, 0700); err != nil {
		return err
	}
	fd, err := unix.Openat(int(parent.Fd()), stageName, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	stage := os.NewFile(uintptr(fd), filepath.Join(parent.Name(), stageName))
	defer stage.Close()
	defer unix.Unlinkat(int(parent.Fd()), stageName, unix.AT_REMOVEDIR)
	out, err := openAt(stage, "payload", true)
	if err != nil {
		return err
	}
	defer out.Close()
	defer removeAt(stage, "payload")
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := copyBounded(ctx, out, src, maxFileSize); err != nil {
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
		return err
	}
	// linkat never overwrites an existing file or dangling symlink. The source
	// inode stays inside an Agent-owned directory throughout publication.
	return unix.Linkat(int(stage.Fd()), "payload", int(parent.Fd()), name, 0)
}
