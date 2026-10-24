//go:build windows

package filetrace

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// matchPath expands DOS short names without resolving junctions or symlinks.
// ETW and the policy may use different aliases for the same directory. Missing
// leaves (rename/delete events) are retained beneath the nearest existing parent.
// Failure preserves the lexical path and never broadens a watched root.
func matchPath(path string) string {
	path = cleanPath(path)
	if !strings.Contains(path, "~") || len(path) < 3 || path[1:3] != `:\` || len(path) > 32767 {
		return path
	}
	parent, suffix := path, ""
	buf := make([]uint16, 32768)
	for depth := 0; depth < 32; depth++ {
		p, err := windows.UTF16PtrFromString(parent)
		if err != nil {
			return path
		}
		// A fixed maximum avoids trusting a required-size result from the OS.
		n, err := windows.GetLongPathName(p, &buf[0], uint32(len(buf)))
		if err == nil && n > 0 && n < uint32(len(buf)) {
			return cleanPath(windows.UTF16ToString(buf[:n]) + suffix)
		}
		next := filepath.Dir(parent)
		if next == parent || len(next) < 3 {
			return path
		}
		suffix = `\` + filepath.Base(parent) + suffix
		parent = next
	}
	return path
}
