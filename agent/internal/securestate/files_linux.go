//go:build linux

package securestate

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func protectDirectory(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("recovery directory belongs to a different user")
	}
	return os.Chmod(path, 0700)
}

func Lock(dir string) (func(), error) {
	if err := PrivateDir(dir); err != nil {
		return nil, err
	}
	fd, err := unix.Open(filepath.Join(dir, "lock"), unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() { unix.Flock(fd, unix.LOCK_UN); unix.Close(fd) }, nil
		}
		if err != unix.EWOULDBLOCK || time.Now().After(deadline) {
			unix.Close(fd)
			return nil, fmt.Errorf("recovery transaction is locked: %w", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func SyncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func Replace(src, dst string) error {
	if err := os.Rename(src, dst); err != nil {
		return err
	}
	return SyncDirectory(filepath.Dir(dst))
}

func Move(src, dst string) error { return Replace(src, dst) }
