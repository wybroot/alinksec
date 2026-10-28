package filewatch

import "os"

// openDirectory binds enumeration to the directory seen by the caller. Linux
// also opens directories without waiting for special-file I/O.
func openDirectory(path string, expected os.FileInfo) (*os.File, string) {
	d, err := openDirectoryFile(path)
	if err != nil {
		return nil, "directory_unreadable"
	}
	after, err := d.Stat()
	current, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !after.IsDir() || !current.IsDir() ||
		!os.SameFile(expected, after) || !os.SameFile(after, current) || !SafePath(path) {
		d.Close()
		return nil, "path_changed"
	}
	return d, ""
}
