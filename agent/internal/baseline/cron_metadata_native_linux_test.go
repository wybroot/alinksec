//go:build linux

package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestNativeCronMetadata(t *testing.T) {
	if os.Getenv("ALINKSEC_CRON_NATIVE_REQUIRED") != "true" {
		t.Skip("disposable cron container only")
	}
	marker, err := os.ReadFile("/usr/local/lib/alinksec-cron-fixture")
	if err != nil || string(marker) != "isolated-cron-metadata-fixture-v1\n" || os.Geteuid() != 0 {
		t.Fatal("isolated cron fixture required")
	}
	status, statusErr := os.ReadFile("/proc/self/status")
	if _, dockerErr := os.Stat("/.dockerenv"); dockerErr != nil || statusErr != nil || !strings.Contains(string(status), "CapEff:\t00000000000000c1\n") {
		t.Fatal("disposable Docker container with only CHOWN/SETUID/SETGID required")
	}
	raw, err := os.ReadFile("../../../deploy/baseline/packages/cron/linux-baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Items []struct {
			Code  string
			Check json.RawMessage
		}
	}
	if err = json.Unmarshal(raw, &doc); err != nil || len(doc.Items) != 1 {
		t.Fatal("one checked-in cron reference required", err)
	}
	cs, err := ParseCheck(string(doc.Items[0].Check))
	if err != nil {
		t.Fatal(err)
	}
	// All files changed below are private to this explicitly marked container.
	if err = os.WriteFile("/etc/pam.d/cron", []byte("auth required pam_permit.so\naccount required pam_permit.so\nsession required pam_permit.so\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DPKG_ROOT", "/untrusted-database-must-not-be-used")
	for _, c := range []struct {
		name    string
		mode    os.FileMode
		uid     int
		execute bool
		fail    bool
		error   bool
	}{
		{"secure", 0644, 0, true, false, false},
		{"group-writable", 0660, 0, false, true, false},
		{"wrong-owner", 0644, 65534, false, true, false},
		{"root-executable", 0744, 0, true, true, false},
		{"root-symlink", 0644, 0, true, false, true},
		{"dotted-backup", 0777, 0, false, true, false},
		{"access-acl", 0644, 0, true, false, true},
		{"default-acl", 0644, 0, true, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			for _, path := range []string{"/etc/cron.d", "/var/spool/cron/crontabs"} {
				if err = os.RemoveAll(path); err != nil {
					t.Fatal(err)
				}
				if err = os.MkdirAll(path, 0755); err != nil {
					t.Fatal(err)
				}
			}
			// Removing this private startup marker enables the controlled @reboot
			// jobs for this one daemon instance. No other tasks are installed.
			if err = os.Remove("/run/crond.reboot"); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			root := t.TempDir()
			base := filepath.Join(root, "system-marker")
			child := filepath.Join(root, "entry-marker")
			write := func(path, content string, mode os.FileMode) {
				t.Helper()
				if err := os.WriteFile(path, []byte(content), mode); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, mode); err != nil {
					t.Fatal(err)
				}
			}
			write("/etc/crontab", fmt.Sprintf("SHELL=/bin/sh\nPATH=/usr/bin:/bin\n@reboot root /usr/bin/touch %s\n", base), 0644)
			name := "alinksec_fixture"
			if c.name == "dotted-backup" {
				name += ".backup"
			}
			path := "/etc/cron.d/" + name
			content := fmt.Sprintf("SHELL=/bin/sh\nPATH=/usr/bin:/bin\n@reboot root /usr/bin/touch %s\n", child)
			if c.name == "root-symlink" {
				target := filepath.Join(root, "linked-table")
				write(target, content, c.mode)
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			} else {
				write(path, content, c.mode)
			}
			if c.uid != 0 {
				if err := os.Chown(path, c.uid, 0); err != nil {
					t.Fatal(err)
				}
			}
			if c.name == "access-acl" || c.name == "default-acl" {
				args := []string{"-m", "u:65534:r--", path}
				if c.name == "default-acl" {
					args = []string{"-m", "d:u:65534:r-x", "/etc/cron.d"}
				}
				if out, err := exec.Command("/usr/bin/setfacl", args...).CombinedOutput(); err != nil {
					t.Fatalf("mandatory native ACL fixture: %s %v", out, err)
				}
			}
			before := checkCronMetadata(cs)
			if before.Error != c.error || before.Passed != (!c.fail && !c.error) || strings.Contains(before.Actual, child) {
				t.Fatalf("wrong Agent observation: %+v", before)
			}
			cmd := exec.Command("/usr/sbin/cron", "-f", "-L", "15")
			cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); _ = cmd.Wait() }()
			deadline := time.Now().Add(3 * time.Second)
			baseReady := false
			for time.Now().Before(deadline) {
				_, err := os.Stat(base)
				baseReady = err == nil
				if baseReady {
					if c.execute {
						if _, err := os.Stat(child); err == nil {
							break
						}
					}
				}
				time.Sleep(20 * time.Millisecond)
			}
			_, childErr := os.Stat(child)
			if !baseReady || (childErr == nil) != c.execute {
				t.Fatalf("native cron selection mismatch: base=%v child=%v expected=%v", baseReady, childErr == nil, c.execute)
			}
			t.Logf("native cron metadata case=%s native_entry_executed=%v passed=%v error=%v actual=%s message=%s", c.name, childErr == nil, before.Passed, before.Error, before.Actual, before.Message)
		})
	}
	// Mandatory GID and hardlink checks use private roots and actual metadata.
	for _, kind := range []string{"gid", "hardlink"} {
		root := cronFixture(t)
		path := filepath.Join(root, "etc/cron.d/task")
		if kind == "gid" {
			err = os.Chown(path, 0, 65534)
		} else {
			err = os.Link(path, filepath.Join(root, "alias"))
		}
		if err != nil {
			t.Fatal(err)
		}
		r := cronMetadataWithin(cs, root, cronPackage)
		if kind == "gid" && (r.Error || r.Passed) || kind == "hardlink" && (!r.Error || r.Passed) {
			t.Fatalf("native %s: %+v", kind, r)
		}
		t.Logf("native cron boundary case=%s passed=%v error=%v actual=%s message=%s", kind, r.Passed, r.Error, r.Actual, r.Message)
	}
}
