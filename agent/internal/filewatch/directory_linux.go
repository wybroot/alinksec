//go:build linux

package filewatch

import (
	"os"

	"golang.org/x/sys/unix"
)

func openDirectoryFile(path string) (*os.File, error) {
	// Lstat cannot prevent a directory from becoming a FIFO before open.
	// Reject non-directories and final symlinks in the open operation itself.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}
