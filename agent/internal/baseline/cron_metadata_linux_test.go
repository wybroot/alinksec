//go:build linux

package baseline

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func cronProbe(context.Context, int) ItemResult {
	return ItemResult{Actual: "ii \t" + cronPackageVersion}
}

func cronFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/cron.d"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"etc/crontab", "etc/cron.d/task", "etc/cron.d/.placeholder", "etc/cron.d/task.backup"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("SECRET_CRON_COMMAND_NOT_FOR_EVIDENCE\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestCronMetadataCompleteObservations(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("numerical root ownership fixture requires root")
	}
	for _, mode := range []os.FileMode{0644, 0600, 0000} {
		t.Run(fmt.Sprintf("%04o", mode), func(t *testing.T) {
			root := cronFixture(t)
			path := filepath.Join(root, "etc/cron.d/task")
			if err := os.Truncate(path, 16*1024*1024); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			r := cronMetadataWithin(cronSpec(), root, cronProbe)
			if r.Error || !r.Passed || !strings.Contains(r.Actual, "entries=3 checked=5 violations=0") || strings.Contains(r.Actual+r.Message, "SECRET_CRON") {
				t.Fatalf("wrong complete metadata evidence: %+v", r)
			}
		})
	}
	for _, target := range []string{"etc/crontab", "etc/cron.d", "etc/cron.d/.placeholder", "etc/cron.d/task.backup"} {
		t.Run(target, func(t *testing.T) {
			root := cronFixture(t)
			if err := os.Chmod(filepath.Join(root, target), 0777); err != nil {
				t.Fatal(err)
			}
			r := cronMetadataWithin(cronSpec(), root, cronProbe)
			if r.Error || r.Passed || !strings.Contains(r.Actual, "violations=1") || !strings.Contains(r.Actual, target+":mode=0777") {
				t.Fatalf("unsafe metadata not fail: %+v", r)
			}
		})
	}
	root := cronFixture(t)
	if err := os.RemoveAll(filepath.Join(root, "etc/cron.d")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "etc/cron.d"), 0755); err != nil {
		t.Fatal(err)
	}
	if r := cronMetadataWithin(cronSpec(), root, cronProbe); r.Error || !r.Passed || !strings.Contains(r.Actual, "entries=0 checked=2") {
		t.Fatalf("empty directory: %+v", r)
	}
}

func TestCronMetadataErrorsAndBounds(t *testing.T) {
	for _, kind := range []string{"missing", "link", "parent-link", "fifo", "directory", "hardlink", "name", "too-many", "package", "deadline"} {
		t.Run(kind, func(t *testing.T) {
			root := cronFixture(t)
			path := filepath.Join(root, "etc/cron.d/task")
			probe := cronProbe
			switch kind {
			case "missing":
				if err := os.Remove(filepath.Join(root, "etc/crontab")); err != nil {
					t.Fatal(err)
				}
			case "link", "fifo", "directory":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				var err error
				if kind == "link" {
					err = os.Symlink(filepath.Join(root, "etc/crontab"), path)
				}
				if kind == "fifo" {
					err = unix.Mkfifo(path, 0600)
				}
				if kind == "directory" {
					err = os.Mkdir(path, 0755)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "parent-link":
				parent := filepath.Join(root, "etc")
				if err := os.Rename(parent, parent+"-real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(parent+"-real", parent); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, filepath.Join(root, "alias")); err != nil {
					t.Fatal(err)
				}
			case "name":
				if err := os.Rename(path, path+" bad"); err != nil {
					t.Fatal(err)
				}
			case "too-many":
				for i := 0; i < 129; i++ {
					if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("etc/cron.d/many-%03d", i)), nil, 0644); err != nil {
						t.Fatal(err)
					}
				}
			case "package":
				probe = func(context.Context, int) ItemResult { return ItemResult{Error: true, Message: "package unavailable"} }
			case "deadline":
				probe = func(ctx context.Context, _ int) ItemResult {
					<-ctx.Done()
					return ItemResult{Error: true, Message: "deadline"}
				}
			}
			cs := cronSpec()
			cs.TimeoutMs = 100
			start := time.Now()
			r := cronMetadataWithin(cs, root, probe)
			if !r.Error || r.Passed || time.Since(start) > time.Second || strings.Contains(r.Actual+r.Message, "SECRET_CRON") {
				t.Fatalf("ambiguous metadata passed, blocked or leaked: %+v", r)
			}
		})
	}
}

func TestCronMetadataChangesInvalidateEvidence(t *testing.T) {
	for _, kind := range []string{"replace", "mode", "addition", "removal", "parent", "package"} {
		t.Run(kind, func(t *testing.T) {
			root := cronFixture(t)
			calls := 0
			probe := func(context.Context, int) ItemResult {
				calls++
				if calls == 2 {
					path := filepath.Join(root, "etc/cron.d/task")
					var err error
					switch kind {
					case "replace":
						err = os.Rename(path, path+"-old")
						if err == nil {
							err = os.WriteFile(path, nil, 0644)
						}
					case "mode":
						err = os.Chmod(path, 0600)
					case "addition":
						err = os.WriteFile(path+"-new", nil, 0644)
					case "removal":
						err = os.Remove(path)
					case "parent":
						err = os.Chmod(filepath.Join(root, "etc"), 0700)
					case "package":
						return ItemResult{Error: true, Message: "changed package"}
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				return cronProbe(context.Background(), 1000)
			}
			if r := cronMetadataWithin(cronSpec(), root, probe); !r.Error || r.Passed {
				t.Fatalf("changed snapshot accepted: %+v", r)
			}
		})
	}
}
