//go:build !linux

package guard

import (
	"os"
	"path/filepath"
)

func fileOwner(os.FileInfo) (int, int) { return -1, -1 }

func directoryIdentity(os.FileInfo) string { return "" }

func replaceProtectedFile(dir *os.File, temporary, name string) error {
	return os.Rename(filepath.Join(dir.Name(), temporary), filepath.Join(dir.Name(), name))
}
