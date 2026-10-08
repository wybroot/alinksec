//go:build linux

package baseline

import (
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sudoersProbe(context.Context, int) ItemResult {
	return ItemResult{Actual: "ii \t" + sudoPackageVersion}
}
func sudoersFixture(t *testing.T, main string, includes map[string]string) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("numeric UID0 fixture requires root")
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/sudoers.d"), 0755); err != nil {
		t.Fatal(err)
	}
	for name, content := range includes {
		if err := os.WriteFile(filepath.Join(root, "etc/sudoers.d", name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "etc/sudoers"), []byte(main), 0644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestSudoersRefusesUnsafeInputs(t *testing.T) {

	for _, kind := range []string{"missing", "symlink", "hardlink", "fifo", "writable", "access-acl", "default-acl", "too-large", "unterminated", "directory-entry", "too-many-files"} {
		t.Run(kind, func(t *testing.T) {
			root := sudoersFixture(t, "Defaults authenticate\n@includedir /etc/sudoers.d\n", map[string]string{"50-grant": "root ALL=(ALL:ALL) ALL\n"})
			path := filepath.Join(root, "etc/sudoers.d/50-grant")
			var err error
			switch kind {
			case "missing":
				err = os.Remove(filepath.Join(root, "etc/sudoers"))
			case "symlink":
				err = os.Rename(path, path+".original")
				if err == nil {
					err = os.Symlink(path+".original", path)
				}
			case "hardlink":
				err = os.Link(path, path+".alias")
			case "fifo":
				err = os.Remove(path)
				if err == nil {
					err = unix.Mkfifo(path, 0600)
				}
			case "writable":
				err = os.Chmod(path, 0666)
			case "access-acl":
				err = unix.Setxattr(path, "system.posix_acl_access", logACL(), 0)
			case "default-acl":
				err = unix.Setxattr(filepath.Dir(path), "system.posix_acl_default", logACL(), 0)
			case "too-large":
				err = os.WriteFile(path, []byte(strings.Repeat("#", 64*1024)+"\n"), 0644)
			case "unterminated":
				err = os.WriteFile(path, []byte("root ALL=(ALL:ALL) ALL"), 0644)
			case "directory-entry":
				err = os.Remove(path)
				if err == nil {
					err = os.Mkdir(path, 0755)
				}
			case "too-many-files":
				for i := 0; i < 33; i++ {
					err = os.WriteFile(filepath.Join(filepath.Dir(path), fmt.Sprintf("%02d-fixture", i)), []byte("#empty\n"), 0644)
					if err != nil {
						break
					}
				}
			}
			if err != nil {
				if os.Getenv("ALINKSEC_SUDOERS_NATIVE_REQUIRED") != "true" && (kind == "access-acl" || kind == "default-acl") && (err == unix.EINVAL || err == unix.EOPNOTSUPP) {
					t.Skip("local filesystem cannot create ACL fixture; mandatory native container covers it")
				}
				t.Fatal(err)
			}
			if r := sudoersWithin(sudoersSpec("authentication"), root, sudoersProbe); !r.Error || r.Passed {
				t.Fatalf("accepted boundary %+v", r)
			}
		})
	}
}

func TestSudoersChangesAndOneDeadline(t *testing.T) {
	for _, kind := range []string{"content", "replacement", "directory", "package", "timeout"} {
		t.Run(kind, func(t *testing.T) {
			root := sudoersFixture(t, "Defaults authenticate\n@includedir /etc/sudoers.d\n", map[string]string{"50-grant": "root ALL=(ALL:ALL) ALL\n"})
			calls := 0
			probe := func(ctx context.Context, _ int) ItemResult {
				calls++
				if calls == 2 {
					path := filepath.Join(root, "etc/sudoers.d/50-grant")
					switch kind {
					case "content":
						if err := os.WriteFile(path, []byte("root ALL=(ALL:ALL) NOPASSWD: ALL\n"), 0644); err != nil {
							t.Fatal(err)
						}
					case "replacement":
						if err := os.Rename(path, path+".backup"); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(path, []byte("root ALL=(ALL:ALL) ALL\n"), 0644); err != nil {
							t.Fatal(err)
						}
					case "directory":
						if err := os.WriteFile(filepath.Join(filepath.Dir(path), "10-grant"), []byte("root ALL=(ALL:ALL) NOPASSWD: ALL\n"), 0644); err != nil {
							t.Fatal(err)
						}
					case "package":
						return ItemResult{Error: true, Message: "package changed"}
					case "timeout":
						<-ctx.Done()
					}
				}
				return sudoersProbe(ctx, 0)
			}
			cs := sudoersSpec("authentication")
			cs.TimeoutMs = 100
			start := time.Now()
			r := sudoersWithin(cs, root, probe)
			if !r.Error || r.Passed || time.Since(start) > time.Second {
				t.Fatalf("change/deadline accepted %+v", r)
			}
		})
	}
}

type sudoersCase struct {
	name, main         string
	includes           map[string]string
	auth, logging      bool
	nopasswd, commands int
}

func sudoersCases() []sudoersCase {
	return []sudoersCase{
		{"explicit", "Defaults authenticate, !exempt_group, log_allowed, logfile=\"/var/log/sudo.log\"\nroot ALL=(ALL:ALL) ALL\n", nil, true, true, 0, 1},
		{"vendor-unset", "Defaults env_reset\nDefaults mail_badpass\nDefaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin\"\nDefaults use_pty\nroot ALL=(ALL:ALL) ALL\n%admin ALL=(ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n", map[string]string{"README": "# vendor comments\n"}, false, false, 0, 3},
		{"comment", "Defaults authenticate,log_allowed\n# NOPASSWD: ALL\n# Defaults logfile=/var/log/sudo.log\nroot ALL=(root) PASSWD: /usr/bin/true # NOPASSWD\n", nil, true, false, 0, 1},
		{"inherit", "Defaults authenticate,log_allowed,logfile=/var/log/sudo.log\nroot ALL=(root) NOPASSWD: /usr/bin/true, /usr/bin/false, PASSWD: /usr/bin/id, /usr/bin/whoami\n", nil, false, true, 2, 4},
		{"tag-reset", "Defaults authenticate\nroot ALL=(root) NOPASSWD: /usr/bin/true\nroot ALL=(root) /usr/bin/false\n", nil, false, false, 1, 2},
		{"overridden-grant", "Defaults authenticate\nroot ALL=(root) NOPASSWD: ALL\nroot ALL=(root) PASSWD: ALL\n", nil, false, false, 1, 2},
		{"authenticate-off", "Defaults authenticate\nDefaults !authenticate,log_allowed,logfile=/var/log/sudo.log\nroot ALL=(root) PASSWD: ALL\n", nil, false, true, 0, 1},
		{"exempt-group", "Defaults authenticate,exempt_group=root\nroot ALL=(root) ALL\n", nil, false, false, 0, 1},
		{"clear-exempt", "Defaults exempt_group=\"root\",!exempt_group,authenticate\nroot ALL=(root) ALL\n", nil, true, false, 0, 1},
		{"logging-off", "Defaults authenticate,log_allowed,logfile=/var/log/sudo.log\nDefaults !log_allowed\nroot ALL=(ALL) ALL\n", nil, true, false, 0, 1},
		{"logfile-off", "Defaults authenticate,log_allowed,logfile=/var/log/sudo.log\nDefaults !logfile\nroot ALL=(ALL) ALL\n", nil, true, false, 0, 1},
		{"other-logfile", "Defaults authenticate,log_allowed,logfile=/var/log/other.log\nroot ALL=(ALL) ALL\n", nil, true, false, 0, 1},
		{"include-position", "Defaults authenticate,log_allowed,logfile=/var/log/sudo.log\n@includedir /etc/sudoers.d\nDefaults authenticate,log_allowed\nroot ALL=(root) ALL\n", map[string]string{"10-off": "Defaults !authenticate,!log_allowed\n", "20-on": "Defaults authenticate\n", "30-grant": "%sudo ALL=(ALL:ALL) ALL\n", "README": "# comments\n", "00.ignore": "Unknown ignored\n", "01-backup~": "Unknown ignored\n"}, true, true, 0, 2},
		{"include-order", "Defaults authenticate,log_allowed,logfile=/var/log/sudo.log\n#includedir /etc/sudoers.d\nroot ALL=(root) ALL\n", map[string]string{"10-on": "Defaults authenticate\n", "20-off": "Defaults !authenticate\n"}, false, true, 0, 1},
		{"include-nopasswd", "Defaults authenticate\n@includedir /etc/sudoers.d\nroot ALL=(root) ALL\n", map[string]string{"10-grant": "%sudo ALL=(ALL:ALL) NOPASSWD: ALL\n"}, false, false, 1, 2},
		{"empty", "Defaults authenticate,log_allowed,logfile=/var/log/sudo.log\n", nil, false, false, 0, 0},
	}
}

func TestSudoersDeclarationGraph(t *testing.T) {
	for _, c := range sudoersCases() {
		t.Run(c.name, func(t *testing.T) {
			root := sudoersFixture(t, c.main, c.includes)
			for option, want := range map[string]bool{"authentication": c.auth, "allowed_logging": c.logging} {
				r := sudoersWithin(sudoersSpec(option), root, sudoersProbe)
				if r.Error || r.Passed != want || !strings.Contains(r.Actual, fmt.Sprintf("nopasswd_tags=%d", c.nopasswd)) || !strings.Contains(r.Actual, fmt.Sprintf("commands=%d", c.commands)) {
					t.Fatalf("%s: %+v", option, r)
				}
			}
		})
	}
}

func TestSudoersUnknownPolicyCannotPass(t *testing.T) {
	for _, line := range []string{
		"Defaults:root !authenticate", "Defaults@ALL !log_allowed", "Defaults>root !authenticate", "Defaults!/usr/bin/true !authenticate",
		"User_Alias ADMINS = root", "Cmnd_Alias CMDS = ALL", "root localhost=(root) ALL", "root ALL=ALL", "root ALL=(#0) ALL", "#1000 ALL=(root) NOPASSWD: ALL",
		"root ALL=(root) !/usr/bin/true", "root ALL=(root) /usr/bin/true *", "root ALL=(root) /usr/bin/", "root ALL=(root) /usr/bin/../bin/true",
		"root ALL=(root) NOLOG_OUTPUT: ALL", "root ALL=(root) PASSWD: NOPASSWD: ALL", "root ALL=(root) ALL,",
		"Defaults ignore_unknown_defaults", "Defaults group_plugin=/tmp/plugin", "Defaults logfile=\"/var/log/%h\"", "Defaults authenticate=true",
		"#include /tmp/secret", " #includedir /etc/sudoers.d", "@includedir /etc/sudoers.d #comment", "@includedir /tmp/other", "root ALL=(root) ALL\\",
		"Defaults secure_path=\"/tmp\"", "Defaults authenticate\x00", "Defaults authenticate\r",
	} {
		t.Run(line, func(t *testing.T) {
			root := sudoersFixture(t, "Defaults authenticate,log_allowed,logfile=/var/log/sudo.log\nroot ALL=(root) ALL\n"+line+"\n", nil)
			if r := sudoersWithin(sudoersSpec("authentication"), root, sudoersProbe); !r.Error || r.Passed || strings.Contains(r.Actual+r.Message, "/tmp/secret") {
				t.Fatalf("accepted unknown policy: %+v", r)
			}
		})
	}
	for _, includes := range []map[string]string{
		{"10-child": "@includedir /etc/sudoers.d\n"}, {"10-a": "#a\n", "10-b": "#b\n"}, {"grant": "root ALL=(root) ALL\n"},
	} {
		root := sudoersFixture(t, "Defaults authenticate\n@includedir /etc/sudoers.d\nroot ALL=(root) ALL\n", includes)
		if r := sudoersWithin(sudoersSpec("authentication"), root, sudoersProbe); !r.Error || r.Passed {
			t.Fatalf("accepted ambiguous include %+v", r)
		}
	}
}
