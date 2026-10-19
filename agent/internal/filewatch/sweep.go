package filewatch

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type frame struct {
	path  string
	dir   *os.File
	depth int
}

// Sweep keeps at most MaxDepth+1 directory descriptors and resumes where the
// previous batch stopped. Large trees cannot starve their later entries merely
// because a single check hit its time/file budget.
type Sweep struct {
	roots   []string
	stack   []frame
	Issue   string
	Entries uint64
}

func NewSweep(roots []string) *Sweep {
	s := &Sweep{roots: append([]string(nil), roots...)}
	if len(s.roots) > MaxRoots {
		s.roots = s.roots[:MaxRoots]
		s.Issue = "root_limit"
	}
	return s
}

func (s *Sweep) Close() {
	for _, f := range s.stack {
		f.dir.Close()
	}
	s.stack = nil
	s.roots = nil
}

func (s *Sweep) open(path string, depth int) string {
	if !SafePath(path) {
		s.Issue = "unsafe_path"
		return ""
	}
	info, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			s.Issue = "directory_unreadable"
		}
		return ""
	}
	if info.Mode().IsRegular() {
		return path
	}
	if !info.IsDir() || depth > MaxDepth {
		return ""
	}
	d, err := os.Open(path)
	if err != nil {
		s.Issue = "directory_unreadable"
		return ""
	}
	after, err := d.Stat()
	if err != nil || !os.SameFile(info, after) || !SafePath(path) {
		d.Close()
		s.Issue = "path_changed"
		return ""
	}
	s.stack = append(s.stack, frame{path, d, depth})
	return ""
}

// Next returns at most one regular file. work/time bound metadata traversal,
// including empty directories and rejected entries. done is true only at EOF.
func (s *Sweep) Next(deadline time.Time) (path string, done bool) {
	for work := 0; work < 512 && time.Now().Before(deadline); work++ {
		if len(s.stack) == 0 {
			if len(s.roots) == 0 {
				return "", true
			}
			root := s.roots[0]
			s.roots = s.roots[1:]
			if p := s.open(root, 0); p != "" {
				return p, false
			}
			continue
		}
		f := s.stack[len(s.stack)-1]
		list, err := f.dir.ReadDir(1)
		if len(list) > 0 {
			s.Entries++
			e := list[0]
			if e.Type()&os.ModeSymlink != 0 || e.IsDir() && (strings.HasPrefix(e.Name(), ".") || f.depth >= MaxDepth) {
				continue
			}
			if p := s.open(filepath.Join(f.path, e.Name()), f.depth+1); p != "" {
				return p, false
			}
		}
		if err != nil {
			if err != io.EOF {
				s.Issue = "directory_unreadable"
			}
			f.dir.Close()
			s.stack = s.stack[:len(s.stack)-1]
		}
	}
	return "", false
}
