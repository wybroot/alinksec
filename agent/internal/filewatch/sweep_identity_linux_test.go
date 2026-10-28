//go:build linux

package filewatch

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestSweepReplacedDirectoryDoesNotMixEntries(t *testing.T) {
	for _, nested := range []bool{false, true} {
		name := "root"
		if nested {
			name = "nested"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			changing := root
			if nested {
				changing = filepath.Join(root, "sub")
				if err := os.Mkdir(changing, 0700); err != nil {
					t.Fatal(err)
				}
			}
			writeSweepFiles(t, changing, "one", "two")
			other := t.TempDir()
			writeSweepFiles(t, other, "later-one", "later-two")
			s := NewSweep([]string{root, other})
			defer s.Close()
			first, done := s.Next(time.Now().Add(time.Second))
			if done || !Within(first, changing) {
				t.Fatalf("changing directory was not opened: path=%q done=%v", first, done)
			}
			if err := os.Rename(changing, filepath.Join(t.TempDir(), "retired")); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(changing, 0700); err != nil {
				t.Fatal(err)
			}
			// Old names make mixing a retired descriptor's entries with the new
			// path observable; new-only is absent from the old directory cursor.
			writeSweepFiles(t, changing, "one", "two", "new-only")
			seen := finishIdentitySweep(t, s)
			for _, p := range seen {
				if Within(p, changing) {
					t.Errorf("retired directory cursor dispatched replacement path %q", p)
				}
			}
			if s.Issue != "path_changed" {
				t.Errorf("directory replacement lost coverage without an issue: %q", s.Issue)
			}
			if countSweepPaths(seen, other) != 2 {
				t.Fatalf("replacement prevented later root progress: %v", seen)
			}
			next := NewSweep([]string{root})
			defer next.Close()
			if got := finishIdentitySweep(t, next); countSweepPaths(got, changing) != 3 || next.Issue != "" {
				t.Fatalf("fresh sweep did not recover replacement contents: paths=%v issue=%q", got, next.Issue)
			}
		})
	}
}

func TestSweepMissingOrLinkedDirectoryReportsGap(t *testing.T) {
	for _, replacement := range []string{"missing", "symlink"} {
		t.Run(replacement, func(t *testing.T) {
			root := t.TempDir()
			writeSweepFiles(t, root, "only-entry")
			s := NewSweep([]string{root})
			defer s.Close()
			if p, done := s.Next(time.Now().Add(time.Second)); p == "" || done {
				t.Fatal("directory cursor was not retained")
			}
			retired := filepath.Join(t.TempDir(), "retired")
			if err := os.Rename(root, retired); err != nil {
				t.Fatal(err)
			}
			if replacement == "symlink" {
				if err := os.Symlink(retired, root); err != nil {
					t.Fatal(err)
				}
			}
			if got := finishIdentitySweep(t, s); len(got) != 0 || s.Issue != "path_changed" {
				t.Fatalf("changed directory at EOF silently accepted: paths=%v issue=%q", got, s.Issue)
			}
		})
	}
}

func writeSweepFiles(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("harmless sweep identity fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func finishIdentitySweep(t *testing.T, s *Sweep) []string {
	t.Helper()
	var seen []string
	for n := 0; n < 100; n++ {
		p, done := s.Next(time.Now().Add(time.Second))
		if p != "" {
			seen = append(seen, p)
		}
		if done {
			return seen
		}
	}
	t.Fatal("sweep stopped making progress")
	return seen
}

func countSweepPaths(paths []string, root string) int {
	count := 0
	for _, p := range paths {
		if Within(p, root) {
			count++
		}
	}
	return count
}

func TestSweepUnavailableRootReportsGapAndRecovers(t *testing.T) {
	for _, kind := range []string{"missing", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			unavailable := filepath.Join(t.TempDir(), "root")
			if kind == "fifo" {
				if err := unix.Mkfifo(unavailable, 0600); err != nil {
					t.Fatal(err)
				}
			}
			other := t.TempDir()
			writeSweepFiles(t, other, "later-one", "later-two")
			s := NewSweep([]string{unavailable, other})
			defer s.Close()
			paths := finishIdentitySweep(t, s)
			if s.Issue != "root_unavailable" || countSweepPaths(paths, other) != 2 {
				t.Errorf("unavailable configured root silently completed or blocked other roots: issue=%q paths=%v", s.Issue, paths)
			}
			if kind == "fifo" {
				if err := os.Remove(unavailable); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Mkdir(unavailable, 0700); err != nil {
				t.Fatal(err)
			}
			writeSweepFiles(t, unavailable, "created-later")
			next := NewSweep([]string{unavailable, other})
			defer next.Close()
			paths = finishIdentitySweep(t, next)
			if next.Issue != "" || countSweepPaths(paths, unavailable) != 1 || countSweepPaths(paths, other) != 2 {
				t.Fatalf("new sweep failed to recover created root: issue=%q paths=%v", next.Issue, paths)
			}
		})
	}
}
