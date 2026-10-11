//go:build linux

package baseline

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const bashFixtureVendor = "# isolated unit fixture startup prefix\n"
const bashFixtureVersions = "ii \tbase-files\t13ubuntu10.5\nii \tbash\t5.2.21-2ubuntu4"

func bashPolicyFixture(t *testing.T, rc, profile string, parts map[string]string) bashPolicyPaths {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	etc := filepath.Join(root, "etc")
	if err := os.MkdirAll(filepath.Join(etc, "profile.d"), 0755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"profile": bashFixtureVendor + profile, "bash.bashrc": bashFixtureVendor + rc} {
		if err := os.WriteFile(filepath.Join(etc, name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range parts {
		if err := os.WriteFile(filepath.Join(etc, "profile.d", name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	signature := bashVendorPrefix{len(bashFixtureVendor), fmt.Sprintf("%x", sha256.Sum256([]byte(bashFixtureVendor)))}
	return bashPolicyPaths{etc: etc, profile: signature, bashrc: signature, uid: uint32(os.Geteuid()), gid: uint32(os.Getegid())}
}
func bashPolicyMock(context.Context, int) ItemResult { return ItemResult{Actual: bashFixtureVersions} }
func runBashPolicy(s CheckSpec, p bashPolicyPaths, q func(context.Context, int) ItemResult) ItemResult {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.TimeoutMs)*time.Millisecond)
	defer cancel()
	return bashPolicyWithin(ctx, &s, p, q)
}
func TestBashStartupOrderingAndScope(t *testing.T) {
	p := bashPolicyFixture(t, "umask 022\nHISTSIZE=1000\nHISTFILESIZE=1000\n", "umask 077\n", map[string]string{"10-base.sh": "TMOUT=0\numask 000\n", "90-policy.sh": "export TMOUT=600\nreadonly TMOUT\numask 027\nHISTTIMEFORMAT='%F %T %z '\n", ".hidden.sh": "arbitrary must never be read\n", "backup.txt": "arbitrary must never be read\n"})
	for option := range bashPolicyReferences {
		r := runBashPolicy(bashPolicySpec(option), p, bashPolicyMock)
		if r.Error || r.Passed != (option != "nonlogin_umask") {
			t.Fatal(option, r)
		}
		for _, key := range []string{"startup_environment", "personal_startup", "invocation", "existing_shell", "timeout_enforcement", "history_delivery"} {
			if !strings.Contains(r.Actual, key+"_state=unverified") {
				t.Fatal("missing scope", r)
			}
		}
		if !strings.Contains(r.Actual, "snapshot_state=non_atomic") {
			t.Fatal(r)
		}
	}
	if err := os.WriteFile(filepath.Join(p.etc, "profile.d", "99-unknown.sh"), []byte("touch /tmp/DO_NOT_EXECUTE\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if r := runBashPolicy(bashPolicySpec("login_timeout"), p, bashPolicyMock); !r.Error || r.Passed {
		t.Fatal(r)
	}
	if r := runBashPolicy(bashPolicySpec("nonlogin_umask"), p, bashPolicyMock); r.Error || r.Passed {
		t.Fatal("login-only files must not affect nonlogin", r)
	}
}
func TestBashStartupFiniteInputsAndLimits(t *testing.T) {
	for _, kind := range []string{"prefix", "control", "invalid_utf8", "unterminated", "long_line", "lines", "file_bytes", "total_bytes", "fragments", "directory_entries", "invalid_name", "non_ascii_name", "readonly_override"} {
		t.Run(kind, func(t *testing.T) {
			p := bashPolicyFixture(t, "umask 027\n", "", nil)
			part := filepath.Join(p.etc, "profile.d", "policy.sh")
			body := "HISTSIZE=1000\n"
			switch kind {
			case "prefix":
				body = "changed\n"
				part = filepath.Join(p.etc, "profile")
			case "control":
				body = "DO_NOT_REPORT_SECRET\x00\n"
			case "invalid_utf8":
				body = "\xff\n"
			case "unterminated":
				body = "HISTSIZE=1000"
			case "long_line":
				body = "#" + strings.Repeat("x", 1024) + "\n"
			case "lines":
				body = strings.Repeat("#\n", 1025)
			case "file_bytes":
				body = strings.Repeat(strings.Repeat("#", 1000)+"\n", 66)
			case "total_bytes":
				body = strings.Repeat(strings.Repeat("#", 1000)+"\n", 64)
				for i := 0; i < 4; i++ {
					if err := os.WriteFile(filepath.Join(p.etc, "profile.d", fmt.Sprintf("%02d.sh", i)), []byte(body), 0644); err != nil {
						t.Fatal(err)
					}
				}
			case "fragments":
				for i := 0; i < 33; i++ {
					if err := os.WriteFile(filepath.Join(p.etc, "profile.d", fmt.Sprintf("%02d.sh", i)), []byte("#\n"), 0644); err != nil {
						t.Fatal(err)
					}
				}
			case "directory_entries":
				for i := 0; i < 129; i++ {
					if err := os.WriteFile(filepath.Join(p.etc, "profile.d", fmt.Sprintf("backup-%03d", i)), nil, 0644); err != nil {
						t.Fatal(err)
					}
				}
			case "invalid_name":
				part = filepath.Join(p.etc, "profile.d", "has space.sh")
			case "non_ascii_name":
				part = filepath.Join(p.etc, "profile.d", "中文.sh")
			case "readonly_override":
				body = "readonly TMOUT=600\nTMOUT=0\n"
			}
			if err := os.WriteFile(part, []byte(body), 0644); err != nil {
				t.Fatal(err)
			}
			r := runBashPolicy(bashPolicySpec("login_timeout"), p, bashPolicyMock)
			if !r.Error || r.Passed || strings.Contains(r.Actual+r.Message, "DO_NOT_REPORT_SECRET") {
				t.Fatal(r)
			}
		})
	}
}
func TestBashStartupUnsafeInputs(t *testing.T) {
	for _, target := range []string{"profile", "bash.bashrc", "part", "directory"} {
		for _, kind := range []string{"uid", "gid", "access-acl", "default-acl", "symlink", "hardlink", "fifo", "writable", "unreadable", "missing"} {
			if target != "directory" && kind == "default-acl" || target == "directory" && (kind == "hardlink" || kind == "fifo") {
				continue
			}
			t.Run(target+"/"+kind, func(t *testing.T) {
				p := bashPolicyFixture(t, "umask 027\n", "", map[string]string{"policy.sh": "export TMOUT=600\nreadonly TMOUT\n"})
				input := filepath.Join(p.etc, target)
				if target == "part" {
					input = filepath.Join(p.etc, "profile.d", "policy.sh")
				}
				if target == "directory" {
					input = filepath.Join(p.etc, "profile.d")
				}
				var err error
				switch kind {
				case "uid":
					err = os.Chown(input, 12345, -1)
				case "gid":
					err = os.Chown(input, -1, 12345)
				case "access-acl":
					err = unix.Setxattr(input, "system.posix_acl_access", logACL(), 0)
				case "default-acl":
					err = unix.Setxattr(input, "system.posix_acl_default", logACL(), 0)
				case "writable":
					err = os.Chmod(input, 0777)
				case "unreadable":
					if target == "directory" {
						err = os.Chmod(input, 0700)
					} else {
						err = os.Chmod(input, 0600)
					}
				case "missing":
					err = os.Rename(input, input+".missing")
				case "symlink":
					err = os.Rename(input, input+".original")
					if err == nil {
						err = os.Symlink(input+".original", input)
					}
				case "hardlink":
					err = os.Link(input, input+".other")
				case "fifo":
					err = os.Remove(input)
					if err == nil {
						err = unix.Mkfifo(input, 0600)
					}
				}
				if err != nil {
					if os.Getenv("ALINKSEC_BASH_NATIVE_REQUIRED") != "true" && (kind == "uid" || kind == "gid" || strings.Contains(kind, "acl")) && (errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EOPNOTSUPP)) {
						t.Skip("local fixture unavailable; mandatory isolated runner must execute")
					}
					t.Fatal(err)
				}
				start := time.Now()
				r := runBashPolicy(bashPolicySpec("login_timeout"), p, bashPolicyMock)
				wantError := !(target == "part" && kind == "missing")
				if r.Error != wantError || r.Passed || time.Since(start) > 2*time.Second {
					t.Fatal(r)
				}
			})
		}
	}
}
func TestBashStartupChangesAndOneDeadline(t *testing.T) {
	for _, kind := range []string{"version", "query_error", "replacement", "permission", "late_acl", "membership", "deadline"} {
		t.Run(kind, func(t *testing.T) {
			p := bashPolicyFixture(t, "umask 027\n", "", nil)
			s := bashPolicySpec("login_umask")
			s.TimeoutMs = 100
			calls := 0
			r := runBashPolicy(s, p, func(ctx context.Context, _ int) ItemResult {
				calls++
				if calls == 1 {
					return bashPolicyMock(ctx, 0)
				}
				var err error
				file := filepath.Join(p.etc, "bash.bashrc")
				switch kind {
				case "version":
					return ItemResult{Actual: strings.ReplaceAll(bashFixtureVersions, "13ubuntu10.5", "13ubuntu10.6")}
				case "query_error":
					return ItemResult{Error: true}
				case "replacement":
					err = os.Rename(file, file+".old")
					if err == nil {
						err = os.WriteFile(file, []byte(bashFixtureVendor+"umask 027\n"), 0644)
					}
				case "permission":
					err = os.Chmod(file, 0666)
				case "late_acl":
					err = unix.Setxattr(file, "system.posix_acl_access", logACL(), 0)
				case "membership":
					err = os.WriteFile(filepath.Join(p.etc, "profile.d", "new.sh"), []byte("umask 000\n"), 0644)
				case "deadline":
					<-ctx.Done()
				}
				if err != nil {
					if kind == "late_acl" && os.Getenv("ALINKSEC_BASH_NATIVE_REQUIRED") != "true" && (err == unix.EINVAL || err == unix.EOPNOTSUPP) {
						t.Skip("native ACL fixture mandatory")
					}
					t.Fatal(err)
				}
				return bashPolicyMock(ctx, 0)
			})
			if !r.Error || r.Passed {
				t.Fatal(r)
			}
		})
	}
	for _, version := range []string{"", "ii \tbase-files\t14ubuntu1\nii \tbash\t5.3", "DO_NOT_REPORT_SECRET"} {
		p := bashPolicyFixture(t, "", "", nil)
		r := runBashPolicy(bashPolicySpec("login_timeout"), p, func(context.Context, int) ItemResult { return ItemResult{Actual: version} })
		if !r.Error || strings.Contains(r.Actual+r.Message, "DO_NOT_REPORT_SECRET") {
			t.Fatal(r)
		}
	}
}
