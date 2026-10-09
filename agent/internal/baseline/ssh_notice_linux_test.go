//go:build linux

package baseline

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const noticeFixtureText = "Authorized access only.\nActivity may be monitored and recorded.\n"

func noticeFixture(t *testing.T) (CheckSpec, sshNoticePaths) {
	t.Helper()
	root := t.TempDir()
	paths := sshNoticePaths{directory: filepath.Join(root, "ssh"), banner: filepath.Join(root, "issue.net"), uid: uint32(os.Geteuid()), gid: uint32(os.Getegid())}
	if err := os.Mkdir(paths.directory, 0700); err != nil {
		t.Fatal(err)
	}
	noticeWrite(t, filepath.Join(paths.directory, "sshd_config"), "UseDNS no\nBanner "+paths.banner+"\n")
	noticeWrite(t, paths.banner, noticeFixtureText)
	s := noticeTestSpec("banner")
	s.Expected = "file=" + sshNoticeBanner + ",sha256=" + fmt.Sprintf("%x", sha256.Sum256([]byte(noticeFixtureText)))
	return s, paths
}
func noticeWrite(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
}
func noticeMock(paths sshNoticePaths) sshNoticeQuery {
	return func(context.Context, string, *SSHConnection, int) ItemResult {
		return ItemResult{Actual: "usedns no\nbanner " + paths.banner + "\n"}
	}
}
func noticeRun(s CheckSpec, paths sshNoticePaths, query sshNoticeQuery) ItemResult {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.TimeoutMs)*time.Millisecond)
	defer cancel()
	return sshNoticeWithin(ctx, &s, paths, query)
}

func TestSSHNoticeContentReferenceAndRedaction(t *testing.T) {
	for _, tc := range []struct {
		name, text           string
		pass, executionError bool
	}{
		{"approved", noticeFixtureText, true, false}, {"changed", "DO_NOT_REPORT_PRIVATE_NOTICE\n", false, false},
		{"empty", "", false, false}, {"blank", " \t\n", false, false},
		{"utf8", "\xff", false, true}, {"escape", "\x1b[31mnotice", false, true}, {"too-large", strings.Repeat("x", 16385), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, p := noticeFixture(t)
			noticeWrite(t, p.banner, tc.text)
			result := noticeRun(s, p, noticeMock(p))
			if result.Passed != tc.pass || result.Error != tc.executionError || strings.Contains(result.Actual+result.Message, "DO_NOT_REPORT_PRIVATE_NOTICE") {
				t.Fatalf("content classification/redaction: %+v", result)
			}
			if !strings.Contains(result.Actual, "banner_delivery_state=unverified") || !strings.Contains(result.Actual, "snapshot_state=non_atomic") {
				t.Fatalf("missing boundaries: %+v", result)
			}
		})
	}
	for _, value := range []string{"none", "/etc/shadow", "/does/not/exist"} {
		t.Run(value, func(t *testing.T) {
			s, p := noticeFixture(t)
			if err := os.Remove(p.banner); err != nil {
				t.Fatal(err)
			}
			result := noticeRun(s, p, func(context.Context, string, *SSHConnection, int) ItemResult {
				return ItemResult{Actual: "usedns no\nbanner " + value}
			})
			if result.Error || result.Passed || !strings.Contains(result.Actual, "content_state=not_") {
				t.Fatalf("alternate path must fail without reading it: %+v", result)
			}
		})
	}
}

func TestSSHNoticeUnsafeInputs(t *testing.T) {
	for _, target := range []string{"sshd_config", "dropin", "banner", "directory"} {
		for _, kind := range []string{"symlink", "hardlink", "fifo", "writable", "access-acl", "default-acl", "uid", "gid"} {
			if target == "directory" && (kind == "hardlink" || kind == "fifo") {
				continue
			}
			if target != "directory" && kind == "default-acl" {
				continue
			}
			t.Run(target+"/"+kind, func(t *testing.T) {
				s, p := noticeFixture(t)
				path := filepath.Join(p.directory, "sshd_config")
				if target == "banner" {
					path = p.banner
				}
				if target == "dropin" {
					path = filepath.Join(p.directory, "part.conf")
					noticeWrite(t, path, "UseDNS no\n")
					noticeWrite(t, filepath.Join(p.directory, "sshd_config"), "Include "+path+"\nBanner "+p.banner+"\n")
				}
				if target == "directory" {
					path = p.directory
				}
				var err error
				switch kind {
				case "symlink":
					backup := path + ".real"
					err = os.Rename(path, backup)
					if err == nil {
						err = os.Symlink(backup, path)
					}
				case "hardlink":
					err = os.Link(path, path+".other")
				case "fifo":
					err = os.Remove(path)
					if err == nil {
						err = unix.Mkfifo(path, 0600)
					}
				case "writable":
					err = os.Chmod(path, 0777)
				case "access-acl":
					err = unix.Setxattr(path, "system.posix_acl_access", logACL(), 0)
				case "default-acl":
					err = unix.Setxattr(path, "system.posix_acl_default", logACL(), 0)
				case "uid":
					err = os.Chown(path, 12345, -1)
				case "gid":
					err = os.Chown(path, -1, 12345)
				}
				if err != nil {
					if os.Getenv("ALINKSEC_SSH_NOTICE_NATIVE_REQUIRED") != "true" && (kind == "uid" || kind == "gid") && (errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EPERM)) {
						t.Skip("local ownership fixture unavailable; mandatory root runner must cover it")
					}
					if os.Getenv("ALINKSEC_SSH_NOTICE_NATIVE_REQUIRED") != "true" && (kind == "access-acl" || kind == "default-acl") && (err == unix.EINVAL || err == unix.EOPNOTSUPP) {
						t.Skip("local filesystem cannot create ACL; mandatory native runner must cover it")
					}
					t.Fatal(err)
				}
				start := time.Now()
				result := noticeRun(s, p, noticeMock(p))
				if !result.Error || result.Passed || time.Since(start) > 2*time.Second {
					t.Fatalf("unsafe input must promptly error: %+v", result)
				}
			})
		}
	}
}

func TestSSHNoticeFiniteIncludeBoundaries(t *testing.T) {
	for _, kind := range []string{"outside", "quoted", "escape", "keyword-equals", "relative-parent", "cycle", "depth", "files", "names", "bytes", "lines", "invalid-utf8", "selected-directory"} {
		t.Run(kind, func(t *testing.T) {
			s, p := noticeFixture(t)
			config := filepath.Join(p.directory, "sshd_config")
			switch kind {
			case "outside":
				noticeWrite(t, config, "Include /etc/passwd\n")
			case "quoted":
				noticeWrite(t, config, "Include \"part.conf\"\n")
			case "escape":
				noticeWrite(t, config, "Include part\\.conf\n")
			case "keyword-equals":
				noticeWrite(t, config, "Include=part.conf\n")
			case "relative-parent":
				noticeWrite(t, config, "Include ../ssh/part.conf\n")
			case "cycle":
				noticeWrite(t, config, "Include sshd_config\n")
			case "depth":
				noticeWrite(t, config, "Include part0.conf\n")
				for i := 0; i < 10; i++ {
					noticeWrite(t, filepath.Join(p.directory, fmt.Sprintf("part%d.conf", i)), fmt.Sprintf("Include part%d.conf\n", i+1))
				}
			case "files", "names":
				noticeWrite(t, config, "Include *.conf\n")
				count := 65
				if kind == "names" {
					count = 129
				}
				for i := 0; i < count; i++ {
					noticeWrite(t, filepath.Join(p.directory, fmt.Sprintf("part%03d.conf", i)), "# private\n")
				}
			case "bytes":
				noticeWrite(t, config, strings.Repeat("#", 65537))
			case "lines":
				noticeWrite(t, config, strings.Repeat("#\n", 1025))
			case "invalid-utf8":
				noticeWrite(t, config, "#\xff\n")
			case "selected-directory":
				noticeWrite(t, config, "Include *.conf\n")
				if err := os.Mkdir(filepath.Join(p.directory, "part.conf"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			result := noticeRun(s, p, func(context.Context, string, *SSHConnection, int) ItemResult {
				calls++
				return ItemResult{Actual: "usedns no\nbanner " + p.banner}
			})
			if !result.Error || result.Passed || calls != 0 {
				t.Fatalf("preflight must reject before native parser: calls=%d result=%+v", calls, result)
			}
		})
	}
}

func TestSSHNoticeTotalBytesIncludesCRLFAndBanner(t *testing.T) {
	s, p := noticeFixture(t)
	noticeWrite(t, filepath.Join(p.directory, "sshd_config"), "Include *.conf\nBanner "+p.banner+"\n")
	for i := 0; i < 16; i++ {
		noticeWrite(t, filepath.Join(p.directory, fmt.Sprintf("part%02d.conf", i)), strings.Repeat("#"+strings.Repeat("a", 60)+"\r\n", 1024))
	}
	text := strings.Repeat("a", 16384)
	noticeWrite(t, p.banner, text)
	s.Expected = "file=" + sshNoticeBanner + ",sha256=" + fmt.Sprintf("%x", sha256.Sum256([]byte(text)))
	calls := 0
	result := noticeRun(s, p, func(context.Context, string, *SSHConnection, int) ItemResult {
		calls++
		return ItemResult{Actual: "usedns no\nbanner " + p.banner}
	})
	if !result.Error || result.Passed || calls != 1 || !strings.Contains(result.Message, "1MiB") {
		t.Fatalf("raw CRLF bytes and selected banner must share aggregate cap: calls=%d result=%+v", calls, result)
	}
}

func TestSSHNoticeChangesAndOneDeadline(t *testing.T) {
	for _, kind := range []string{"config", "banner", "directory", "output", "query-error", "deadline"} {
		t.Run(kind, func(t *testing.T) {
			s, p := noticeFixture(t)
			s.TimeoutMs = 100
			calls := 0
			result := noticeRun(s, p, func(ctx context.Context, _ string, _ *SSHConnection, _ int) ItemResult {
				calls++
				if calls == 2 {
					switch kind {
					case "config":
						noticeWrite(t, filepath.Join(p.directory, "sshd_config"), "UseDNS yes\n")
					case "banner":
						noticeWrite(t, p.banner, "DO_NOT_REPORT_CHANGED_NOTICE\n")
					case "directory":
						noticeWrite(t, filepath.Join(p.directory, "new.conf"), "# added\n")
					case "output":
						return ItemResult{Actual: "usedns yes\nbanner " + p.banner}
					case "query-error":
						return ItemResult{Error: true, Actual: "DO_NOT_REPORT_CONFIG_SECRET"}
					case "deadline":
						<-ctx.Done()
						return ItemResult{Error: true}
					}
				}
				return ItemResult{Actual: "usedns no\nbanner " + p.banner}
			})
			if !result.Error || result.Passed || strings.Contains(result.Actual+result.Message, "DO_NOT_REPORT_") {
				t.Fatalf("changed/deadline input accepted or disclosed: %+v", result)
			}
		})
	}
}

func TestSSHNoticeOptionsAndProductVersion(t *testing.T) {
	for _, output := range []string{"usedns no", "banner none", "usedns true\nbanner none", "usedns no\nbanner none\nbanner /etc/issue.net", "usedns no\nbanner none extra"} {
		if _, err := sshNoticeOptions(output); err == nil {
			t.Fatalf("accepted: %q", output)
		}
	}
	for _, tc := range []struct {
		version string
		valid   bool
	}{{"1:9.6p1-3ubuntu13", true}, {"1:9.6p1-3ubuntu13.19", true}, {"9.6p1-3ubuntu13", false}, {"1:9.6p1-3ubuntu14", false}, {"1:10.2p1-1", false}, {"1:9.6p1-3ubuntu13.1evil", false}} {
		if sshNoticeVersion.MatchString(tc.version) != tc.valid {
			t.Fatalf("version boundary: %s", tc.version)
		}
	}
}
