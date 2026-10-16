//go:build linux

package configguard

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func isLink(i os.FileInfo) bool { return i.Mode()&os.ModeSymlink != 0 }
func openNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var i unix.Stat_t
	if err := unix.Fstat(fd, &i); err != nil || i.Nlink != 1 {
		unix.Close(fd)
		return nil, fmt.Errorf("configuration must have a single link")
	}
	return os.NewFile(uintptr(fd), path), nil
}
func privateFile(path string) error {
	i, err := os.Lstat(path)
	if err != nil {
		return err
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok || !i.Mode().IsRegular() || isLink(i) || s.Uid != uint32(os.Geteuid()) || i.Mode().Perm()&0077 != 0 || s.Nlink != 1 {
		return fmt.Errorf("configuration record is not private")
	}
	return nil
}
func protectFile(path string) error { return os.Chmod(path, 0600) }
func writableParent(path string) error {
	i, err := os.Lstat(path)
	if err != nil {
		return err
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok || !i.IsDir() || isLink(i) || s.Uid != uint32(os.Geteuid()) || i.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("configuration parent is not owned and protected")
	}
	return nil
}
