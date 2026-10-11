//go:build linux

package baseline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const auditdBase = "space_left = 75\nadmin_space_left = 50\n"

func TestAuditdParserRejectsAmbiguousAndUnsupportedConfiguration(t *testing.T) {
	for _, suffix := range []string{
		"write_logs=yes\n", "write_logs = yes # comment\n", "write_logs = yes\nWRITE_LOGS = no\n",
		"write_logs = maybe\n", "unknown = yes\n", "include = /tmp/other\n", "space_left_action = exec /tmp/script\n",
		"log_format = raw|enriched\n", "write_logs = yes|no\n",
		"log_file = /etc/shadow\n", "log_file = /var/log/../etc/shadow\n", "log_file = /var/log/a/./audit.log\n",
		"log_group = 123bad\n", "log_group = adm\n", "log_group = 4294967295\n",
		"name_format = hostname\n", "space_left = 80%\n", "freq = 2147483648\n", "num_logs = 1000\n",
		"plugin_dir = /tmp/plugins\n", "flush = incremental_async\n", "write_logs = yes\r\n", "write_logs\t=\tyes\n",
		"#" + strings.Repeat("x", 158) + "\n", "write_logs = yes", "write_logs = yes\x00\n",
	} {
		t.Run(suffix, func(t *testing.T) {
			if _, err := parseAuditdConfig(auditdBase + suffix); err == nil {
				t.Fatalf("accepted %q", suffix)
			}
		})
	}
	for _, raw := range []string{"", "# empty\n", "space_left = 50\nadmin_space_left = 75\n", strings.Repeat("#\n", 40000)} {
		if _, err := parseAuditdConfig(raw); err == nil {
			t.Fatal("accepted invalid or excessive input")
		}
	}
}

func TestAuditdParserKeepsNativeDefaultsCaseAndNologOrdering(t *testing.T) {
	for _, test := range []struct{ suffix, write, format string }{
		{"", "yes", "enriched"},
		{"WRITE_LOGS = NO\nLOG_FORMAT = RAW\n", "no", "raw"},
		{"log_format = NOLOG\n", "no", "nolog"},
		{"log_format = NOLOG\nwrite_logs = yes\n", "yes", "nolog"},
	} {
		values, err := parseAuditdConfig(auditdBase + test.suffix)
		if err != nil || values["write_logs"] != test.write || values["log_format"] != test.format || values["log_file"] != "/var/log/audit/audit.log" {
			t.Fatalf("%+v %v", values, err)
		}
	}
}

func auditdFixture(t *testing.T, suffix string) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root ownership fixture required")
	}
	root := t.TempDir()
	for _, dir := range []string{"etc/audit", "var/log/audit"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for path, contents := range map[string]string{"etc/audit/auditd.conf": auditdBase + suffix, "var/log/audit/audit.log": "PRIVATE_LOG_DO_NOT_READ"} {
		if err := os.WriteFile(filepath.Join(root, path), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestAuditdDeclaredPolicyAndConfiguredMetadata(t *testing.T) {
	for _, test := range []struct {
		option, suffix         string
		passed, executionError bool
	}{
		{"local_logging", "", true, false},
		{"local_logging", "write_logs = no\n", false, false},
		{"local_logging", "local_events = no\n", false, false},
		{"local_logging", "log_format = nolog\nwrite_logs = yes\n", false, false},
		{"keep_logs", "max_log_file = 8\nmax_log_file_action = keep_logs\n", true, false},
		{"keep_logs", "max_log_file = 8\nmax_log_file_action = rotate\n", false, false},
		{"keep_logs", "max_log_file_action = keep_logs\n", false, false},
		{"log_file_metadata", "", true, false},
		{"log_file_metadata", "log_group = 1234\n", false, false},
		{"log_file_metadata", "log_group = root\n", false, true},
		{"log_file_metadata", "write_logs = no\n", false, false},
	} {
		t.Run(test.option+test.suffix, func(t *testing.T) {
			root := auditdFixture(t, test.suffix)
			r := auditdConfigWithin(auditdSpec(test.option), root)
			if r.Passed != test.passed || r.Error != test.executionError || !strings.Contains(r.Actual, "loaded_state=unverified") || strings.Contains(r.Actual, "PRIVATE_LOG") {
				t.Fatalf("%+v", r)
			}
		})
	}
	root := auditdFixture(t, "log_file = /var/log/audit/custom.log\n")
	if err := os.Rename(filepath.Join(root, "var/log/audit/audit.log"), filepath.Join(root, "var/log/audit/custom.log")); err != nil {
		t.Fatal(err)
	}
	if r := auditdConfigWithin(auditdSpec("log_file_metadata"), root); !r.Passed || !strings.Contains(r.Actual, "custom.log") {
		t.Fatal(r)
	}
	if err := os.Chmod(filepath.Join(root, "var/log/audit/custom.log"), 0660); err != nil {
		t.Fatal(err)
	}
	if r := auditdConfigWithin(auditdSpec("log_file_metadata"), root); r.Passed || r.Error {
		t.Fatal(r)
	}
}

func TestAuditdFileBoundariesAndChanges(t *testing.T) {
	for _, which := range []string{"etc/audit/auditd.conf", "var/log/audit/audit.log"} {
		for _, kind := range []string{"missing", "symlink", "parent-link", "hardlink", "fifo", "directory", "acl", "replaced", "modified"} {
			t.Run(which+kind, func(t *testing.T) {
				root := auditdFixture(t, "")
				path := filepath.Join(root, which)
				if kind == "replaced" || kind == "modified" {
					in, err := openAuditdInput(root, "/"+which)
					if err != nil {
						t.Fatal(err)
					}
					defer in.file.Close()
					if kind == "replaced" {
						if err := os.Rename(path, path+".old"); err != nil {
							t.Fatal(err)
						}
					}
					if err := os.WriteFile(path, []byte("changed"), 0600); err != nil {
						t.Fatal(err)
					}
					if in.stable(which == "etc/audit/auditd.conf") {
						t.Fatal("missed mutation")
					}
					return
				}
				switch kind {
				case "hardlink":
					if err := os.Link(path, path+".alias"); err != nil {
						t.Fatal(err)
					}
				case "parent-link":
					parent := filepath.Dir(path)
					if err := os.Rename(parent, parent+".old"); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(parent+".old", parent); err != nil {
						t.Fatal(err)
					}
				case "acl":
					if err := unix.Setxattr(path, "system.posix_acl_access", logACL(), 0); err != nil {
						if os.Getenv("ALINKSEC_AUDITD_NATIVE_REQUIRED") == "true" {
							t.Fatal(err)
						}
						t.Skip("local filesystem cannot create ACL fixture")
					}
				default:
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					switch kind {
					case "symlink":
						if err := os.Symlink("/etc/shadow", path); err != nil {
							t.Fatal(err)
						}
					case "fifo":
						if err := unix.Mkfifo(path, 0600); err != nil {
							t.Fatal(err)
						}
					case "directory":
						if err := os.Mkdir(path, 0700); err != nil {
							t.Fatal(err)
						}
					}
				}
				start := time.Now()
				r := auditdConfigWithin(auditdSpec("log_file_metadata"), root)
				if !r.Error || r.Passed || time.Since(start) > time.Second {
					t.Fatalf("%+v", r)
				}
			})
		}
	}
	root := auditdFixture(t, "")
	config := filepath.Join(root, "etc/audit/auditd.conf")
	if err := os.Chmod(config, 0660); err != nil {
		t.Fatal(err)
	}
	if r := auditdConfigWithin(auditdSpec("local_logging"), root); !r.Error {
		t.Fatal(r)
	}
}
