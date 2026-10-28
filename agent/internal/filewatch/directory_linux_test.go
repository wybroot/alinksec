//go:build linux

package filewatch

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestOpenDirectoryRejectsReplacementWithoutBlocking(t *testing.T) {
	for _, replacement := range []string{"fifo", "regular", "directory", "symlink"} {
		t.Run(replacement, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "changing")
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			retired := path + "-retired"
			if err := os.Rename(path, retired); err != nil {
				t.Fatal(err)
			}
			// Deterministically replace the path between the caller's directory
			// check and the shared opener used by sweep and watch registration.
			switch replacement {
			case "fifo":
				err = unix.Mkfifo(path, 0600)
			case "regular":
				err = os.WriteFile(path, []byte("harmless replacement"), 0600)
			case "directory":
				err = os.Mkdir(path, 0700)
			case "symlink":
				err = os.Symlink(retired, path)
			}
			if err != nil {
				t.Fatal(err)
			}
			type result struct {
				dir   *os.File
				issue string
			}
			done := make(chan result, 1)
			go func() {
				dir, issue := openDirectory(path, before)
				done <- result{dir, issue}
			}()
			var got result
			select {
			case got = <-done:
			case <-time.After(time.Second):
				// Unblock the old FIFO reader so the regression itself neither
				// leaks a goroutine nor leaves a file descriptor behind.
				if replacement != "fifo" {
					t.Fatal("directory open did not finish")
				}
				fd, err := unix.Open(path, unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer unix.Close(fd)
				select {
				case got = <-done:
				case <-time.After(2 * time.Second):
					t.Fatal("FIFO reader did not stop after being released")
				}
				t.Error("directory open waited for a FIFO writer; traversal deadline cannot interrupt it")
			}
			if got.dir != nil {
				got.dir.Close()
				t.Error("replacement returned an enumeration descriptor")
			}
			if got.issue == "" {
				t.Fatal("replacement lost coverage without reporting an issue")
			}
			// A later attempt with a fresh identity must be able to recover.
			err = os.Remove(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			writeSweepFiles(t, path, "recovered")
			s := NewSweep([]string{path})
			defer s.Close()
			if paths := finishIdentitySweep(t, s); len(paths) != 1 || s.Issue != "" {
				t.Fatalf("new directory did not recover: paths=%v issue=%q", paths, s.Issue)
			}
		})
	}
}

func TestOpenDirectoryReadsOriginalIdentity(t *testing.T) {
	path := t.TempDir()
	writeSweepFiles(t, path, "harmless")
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	d, issue := openDirectory(path, before)
	if issue != "" {
		t.Fatal(issue)
	}
	defer d.Close()
	entries, err := d.ReadDir(-1)
	if err != nil || len(entries) != 1 || entries[0].Name() != "harmless" {
		t.Fatalf("directory enumeration failed: entries=%v err=%v", entries, err)
	}
}
