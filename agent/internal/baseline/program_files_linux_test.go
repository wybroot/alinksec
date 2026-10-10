//go:build linux

package baseline

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func programFilesFixture(t *testing.T) programFilesPaths {
	t.Helper()
	root := t.TempDir()
	p := programFilesPaths{root, runtime.GOARCH, uint32(os.Geteuid()), uint32(os.Getegid())}
	for _, dir := range []string{"/etc/ld.so.conf.d", "/etc/alinksec", "/usr/bin", "/usr/sbin"} {
		if err := os.MkdirAll(p.path(dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	for name, raw := range map[string]string{"/etc/ld.so.conf": "include /etc/ld.so.conf.d/*.conf\n", "/etc/ld.so.conf.d/10-library.conf": "# global configuration\n/usr/local/lib\n", "/etc/alinksec/privileged-files.reference": privilegedReferenceHeader} {
		if err := os.WriteFile(p.path(name), []byte(raw), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return p
}
func fixtureProgramVersions(context.Context, int) ItemResult {
	return ItemResult{Actual: "ii \tlibc-bin\t2.39-0ubuntu8.9\nii \tlibc6\t2.39-0ubuntu8.9"}
}
func programFixtureCheck(t *testing.T, p programFilesPaths, s CheckSpec) ItemResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return programFilesWithin(ctx, &s, p, fixtureProgramVersions)
}
func TestProgramFilesTrustedInputAndLimits(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		mutate               func(programFilesPaths) error
		pass, executionError bool
	}{
		{"supported", func(p programFilesPaths) error { return nil }, true, false},
		{"extra_execute_bit", func(p programFilesPaths) error { return os.Chmod(p.path("/etc/ld.so.conf"), 0755) }, false, false},
		{"writable", func(p programFilesPaths) error { return os.Chmod(p.path("/etc/ld.so.conf"), 0666) }, false, true},
		{"missing_main", func(p programFilesPaths) error { return os.Remove(p.path("/etc/ld.so.conf")) }, false, true},
		{"other_include", func(p programFilesPaths) error {
			return os.WriteFile(p.path("/etc/ld.so.conf"), []byte("include /etc/other/*.conf\n"), 0644)
		}, false, true},
		{"nested_include", func(p programFilesPaths) error {
			return os.WriteFile(p.path("/etc/ld.so.conf.d/10-library.conf"), []byte("include /etc/other/*.conf\n"), 0644)
		}, false, true},
		{"linked_fragment", func(p programFilesPaths) error {
			path := p.path("/etc/ld.so.conf.d/10-library.conf")
			if err := os.Remove(path); err != nil {
				return err
			}
			return os.Symlink("../ld.so.conf", path)
		}, false, true},
		{"hardlinked_main", func(p programFilesPaths) error { return os.Link(p.path("/etc/ld.so.conf"), p.path("/etc/linked")) }, false, true},
		{"fifo_main", func(p programFilesPaths) error {
			path := p.path("/etc/ld.so.conf")
			if err := os.Remove(path); err != nil {
				return err
			}
			return unix.Mkfifo(path, 0644)
		}, false, true},
		{"too_many_fragments", func(p programFilesPaths) error {
			for i := 0; i < 33; i++ {
				if err := os.WriteFile(p.path(fmt.Sprintf("/etc/ld.so.conf.d/%02d.conf", i)), []byte("/lib\n"), 0644); err != nil {
					return err
				}
			}
			return nil
		}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := programFilesFixture(t)
			if err := tc.mutate(p); err != nil {
				t.Fatal(err)
			}
			r := programFixtureCheck(t, p, programFilesSpec("linker_metadata"))
			if r.Passed != tc.pass || r.Error != tc.executionError {
				t.Fatal(r)
			}
		})
	}
}
func TestProgramFilesPrivilegedScopeAndContent(t *testing.T) {
	p := programFilesFixture(t)
	s := programFilesSpec("privileged_reference")
	if r := programFixtureCheck(t, p, s); !r.Passed || r.Error {
		t.Fatal(r)
	}
	file := p.path("/usr/bin/fixture")
	raw := []byte("never-execute-this-file\n")
	if err := os.WriteFile(file, raw, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, os.ModeSetuid|0755); err != nil {
		t.Fatal(err)
	}
	if r := programFixtureCheck(t, p, s); r.Passed || r.Error || !strings.Contains(r.Actual, "observed_entries=1") {
		t.Fatal(r)
	}
	// Numerical production approvals require UID0; ordinary local unit tests
	// still verify mismatch behavior and hashing without claiming root fixtures.
	if os.Geteuid() == 0 {
		ref := privilegedReferenceHeader + p.arch + "\t/usr/bin/fixture\t4755\t0\t0\t" + fmt.Sprintf("%x", sha256.Sum256(raw)) + "\n"
		if err := os.WriteFile(p.path(privilegedReferencePath), []byte(ref), 0644); err != nil {
			t.Fatal(err)
		}
		s.Expected = programReferenceExpected(ref)
		if r := programFixtureCheck(t, p, s); !r.Passed || r.Error {
			t.Fatal(r)
		}
		if err := os.WriteFile(file, []byte("changed"), 0755); err != nil {
			t.Fatal(err)
		}
		os.Chmod(file, os.ModeSetuid|0755)
		if r := programFixtureCheck(t, p, s); r.Passed || r.Error {
			t.Fatal(r)
		}
	}
	if err := os.Link(file, p.path("/usr/sbin/linked")); err != nil {
		t.Fatal(err)
	}
	if r := programFixtureCheck(t, p, s); !r.Error || r.Passed {
		t.Fatal(r)
	}
}
func TestProgramFilesReferencePinAndCommonDeadline(t *testing.T) {
	p := programFilesFixture(t)
	s := programFilesSpec("privileged_reference")
	s.Expected = programReferenceExpected(privilegedReferenceHeader + "\n")
	if r := programFixtureCheck(t, p, s); !r.Error || r.Passed {
		t.Fatal(r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := programFilesWithin(ctx, &s, p, fixtureProgramVersions)
	if !r.Error || r.Passed {
		t.Fatal(r)
	}
}

func TestProgramFilesChangesAreErrors(t *testing.T) {
	for _, which := range []string{"configuration", "membership", "reference", "version", "query", "deadline"} {
		p := programFilesFixture(t)
		s := programFilesSpec("linker_metadata")
		if which == "reference" {
			s = programFilesSpec("privileged_reference")
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		calls := 0
		query := func(ctx context.Context, timeout int) ItemResult {
			calls++
			r := fixtureProgramVersions(ctx, timeout)
			if calls == 2 {
				switch which {
				case "configuration":
					os.WriteFile(p.path("/etc/ld.so.conf"), []byte("changed\n"), 0644)
				case "membership":
					os.WriteFile(p.path("/etc/ld.so.conf.d/new.conf"), []byte("/lib\n"), 0644)
				case "reference":
					os.WriteFile(p.path(privilegedReferencePath), []byte(privilegedReferenceHeader+"\n"), 0644)
				case "version":
					r.Actual = strings.ReplaceAll(r.Actual, "2.39", "2.40")
				case "query":
					r.Error = true
				case "deadline":
					cancel()
				}
			}
			return r
		}
		r := programFilesWithin(ctx, &s, p, query)
		cancel()
		if !r.Error || r.Passed {
			t.Fatal(which, r)
		}
	}
}
