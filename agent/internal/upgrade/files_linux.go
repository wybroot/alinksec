//go:build linux

package upgrade

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

func protectDirectory(path string) error { return os.Chmod(path, 0700) }

func lockUpgrade(workDir string) (func(), error) {
	if err := privateDir(upgradeDir(workDir)); err != nil {
		return nil, err
	}
	fd, err := unix.Open(filepath.Join(upgradeDir(workDir), "lock"), unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
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
			return nil, fmt.Errorf("upgrade transaction is locked: %w", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func replaceRecord(src, dst string) error {
	if err := os.Rename(src, dst); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(dst))
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func moveExecutable(src, dst string) error { return replaceRecord(src, dst) }
