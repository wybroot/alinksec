//go:build linux

package guard

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func directoryIdentity(info os.FileInfo) string {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d:%d", stat.Dev, stat.Ino)
	}
	return ""
}

func fileOwner(info os.FileInfo) (int, int) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(stat.Uid), int(stat.Gid)
	}
	return -1, -1
}

func replaceProtectedFile(dir *os.File, temporary, name string) error {
	return unix.Renameat(int(dir.Fd()), temporary, int(dir.Fd()), name)
}
