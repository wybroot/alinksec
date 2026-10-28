//go:build !linux

package filewatch

import "os"

func openDirectoryFile(path string) (*os.File, error) {
	return os.Open(path)
}
