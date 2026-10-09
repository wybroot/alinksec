//go:build linux

package baseline

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const shadowDefaultsTestVersion = "1:4.13+dfsg1-4ubuntu3.2"

func shadowDefaultsFixture(t *testing.T, body string) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "etc")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "login.defs")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func shadowDefaultsMock(context.Context, int) ItemResult {
	return ItemResult{Actual: shadowDefaultsTestVersion}
}

func runShadowDefaults(s CheckSpec, path string, query shadowDefaultsQuery) ItemResult {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.TimeoutMs)*time.Millisecond)
	defer cancel()
	return shadowDefaultsWithin(ctx, &s, path, uint32(os.Geteuid()), uint32(os.Getegid()), query)
}

func TestShadowDefaultsPoliciesAndFiniteSyntax(t *testing.T) {
	for _, tc := range []struct {
		name, body                string
		max, warn, executionError bool
	}{
		{"positive", "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\n", true, true, false},
		{"comments_crlf", "# PASS_MAX_DAYS 99999\r\n\tPASS_MAX_DAYS\t90\r\nPASS_WARN_AGE 14\r\nMAIL_DIR /var/mail\r\n", true, true, false},
		{"max_too_long", "PASS_MAX_DAYS 99999\nPASS_WARN_AGE 7\n", false, true, false},
		{"warning_too_short", "PASS_MAX_DAYS 90\nPASS_WARN_AGE 0\n", true, false, false},
		{"warning_too_early", "PASS_MAX_DAYS 90\nPASS_WARN_AGE 15\n", true, false, false},
		{"warning_exceeds_max", "PASS_MAX_DAYS 1\nPASS_WARN_AGE 7\n", true, false, false},
		{"min_exceeds_max", "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 91\nPASS_WARN_AGE 7\n", false, true, false},
		{"missing", "# No selected declarations\n", false, false, false},
		{"missing_warning", "PASS_MAX_DAYS 90\n", true, false, false},
		{"disabled", "PASS_MAX_DAYS -1\nPASS_MIN_DAYS -1\nPASS_WARN_AGE -1\n", false, false, false},
		{"zero", "PASS_MAX_DAYS 0\nPASS_WARN_AGE 7\n", false, false, false},
		{"int_max", "PASS_MAX_DAYS 2147483647\nPASS_WARN_AGE 7\n", false, true, false},
		{"unicode_separator", "PASS_MAX_DAYS\u00a090\nPASS_WARN_AGE 7\n", false, false, false},
		{"unicode_value_tail", "PASS_MAX_DAYS 90\u00a0\nPASS_WARN_AGE 7\n", false, false, true},
		{"duplicate", "PASS_MAX_DAYS 99999\nPASS_MAX_DAYS 90\nPASS_WARN_AGE 7\n", false, false, true},
		{"duplicate_min", "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\nPASS_MIN_DAYS 0\nPASS_WARN_AGE 7\n", false, false, true},
		{"quoted", "PASS_MAX_DAYS \"90\"\nPASS_WARN_AGE 7\n", false, false, true},
		{"inline_comment", "PASS_MAX_DAYS 90 # comment\nPASS_WARN_AGE 7\n", false, false, true},
		{"octal", "PASS_MAX_DAYS 0132\nPASS_WARN_AGE 7\n", false, false, true},
		{"hex", "PASS_MAX_DAYS 0x5a\nPASS_WARN_AGE 7\n", false, false, true},
		{"overflow", "PASS_MAX_DAYS 2147483648\nPASS_WARN_AGE 7\n", false, false, true},
		{"unknown_negative", "PASS_MAX_DAYS -2\nPASS_WARN_AGE 7\n", false, false, true},
		{"case", "pass_max_days 90\nPASS_WARN_AGE 7\n", false, false, true},
		{"native_fragment", "#" + strings.Repeat("x", 1022) + "PASS_MAX_DAYS 99999\nPASS_MAX_DAYS 90\nPASS_WARN_AGE 7\n", false, false, true},
		{"invalid_utf8", "PASS_MAX_DAYS 90\n\xff\nPASS_WARN_AGE 7\n", false, false, true},
		{"secret_control", "PASS_MAX_DAYS 90\nDO_NOT_REPORT_SECRET\x00\nPASS_WARN_AGE 7\n", false, false, true},
		{"too_many_lines", strings.Repeat("#\n", 1025), false, false, true},
		{"too_large", strings.Repeat("#\n", 32769), false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := shadowDefaultsFixture(t, tc.body)
			for _, option := range []string{"max_days", "warn_days"} {
				result := runShadowDefaults(shadowDefaultsSpec(option), path, shadowDefaultsMock)
				want := tc.max
				if option == "warn_days" {
					want = tc.warn
				}
				if result.Error != tc.executionError || result.Passed != want || strings.Contains(result.Actual+result.Message, "DO_NOT_REPORT_SECRET") {
					t.Fatalf("%s classification or redaction: %+v", option, result)
				}
				for _, boundary := range []string{"creation_invocation_state=unverified", "existing_account_state=unverified", "expiry_enforcement_state=unverified", "warning_delivery_state=unverified", "snapshot_state=non_atomic"} {
					if !strings.Contains(result.Actual, boundary) {
						t.Fatal("missing scope:", result)
					}
				}
			}
		})
	}
}

func TestShadowDefaultsUnsafeInputs(t *testing.T) {
	for _, target := range []string{"file", "directory"} {
		for _, kind := range []string{"symlink", "hardlink", "fifo", "writable", "access-acl", "default-acl", "uid", "gid", "missing"} {
			if target == "directory" && (kind == "hardlink" || kind == "fifo") || target == "file" && kind == "default-acl" {
				continue
			}
			t.Run(target+"/"+kind, func(t *testing.T) {
				path := shadowDefaultsFixture(t, "PASS_MAX_DAYS 90\nPASS_WARN_AGE 7\n")
				input := path
				if target == "directory" {
					input = filepath.Dir(path)
				}
				var err error
				switch kind {
				case "symlink":
					err = os.Rename(input, input+".real")
					if err == nil {
						err = os.Symlink(input+".real", input)
					}
				case "hardlink":
					err = os.Link(input, input+".other")
				case "fifo":
					err = os.Remove(input)
					if err == nil {
						err = unix.Mkfifo(input, 0600)
					}
				case "writable":
					err = os.Chmod(input, 0777)
				case "access-acl":
					err = unix.Setxattr(input, "system.posix_acl_access", logACL(), 0)
				case "default-acl":
					err = unix.Setxattr(input, "system.posix_acl_default", logACL(), 0)
				case "uid":
					err = os.Chown(input, 12345, -1)
				case "gid":
					err = os.Chown(input, -1, 12345)
				case "missing":
					err = os.Rename(input, input+".missing")
				}
				if err != nil {
					if os.Getenv("ALINKSEC_SHADOW_DEFAULTS_NATIVE_REQUIRED") != "true" && (errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EOPNOTSUPP)) && (kind == "uid" || kind == "gid" || strings.Contains(kind, "acl")) {
						t.Skip("local fixture unavailable; mandatory isolated root runner must execute it")
					}
					t.Fatal(err)
				}
				start := time.Now()
				result := runShadowDefaults(shadowDefaultsSpec("max_days"), path, shadowDefaultsMock)
				if !result.Error || result.Passed || time.Since(start) > 2*time.Second {
					t.Fatalf("unsafe input must promptly error: %+v", result)
				}
			})
		}
	}
}

func TestShadowDefaultsChangesAndOneDeadline(t *testing.T) {
	for _, kind := range []string{"version", "query_error", "file_change", "replacement", "permission", "late_acl", "deadline"} {
		t.Run(kind, func(t *testing.T) {
			path := shadowDefaultsFixture(t, "PASS_MAX_DAYS 90\nPASS_WARN_AGE 7\n")
			s := shadowDefaultsSpec("max_days")
			s.TimeoutMs = 100
			calls := 0
			start := time.Now()
			result := runShadowDefaults(s, path, func(ctx context.Context, _ int) ItemResult {
				calls++
				if calls == 1 {
					return shadowDefaultsMock(ctx, 0)
				}
				switch kind {
				case "version":
					return ItemResult{Actual: "1:4.13+dfsg1-4ubuntu3.99"}
				case "query_error":
					return ItemResult{Error: true}
				case "file_change":
					if err := os.WriteFile(path, []byte("PASS_MAX_DAYS 30\nPASS_WARN_AGE 7\n"), 0600); err != nil {
						t.Fatal(err)
					}
				case "replacement":
					if err := os.Rename(path, path+".old"); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, []byte("PASS_MAX_DAYS 90\nPASS_WARN_AGE 7\n"), 0600); err != nil {
						t.Fatal(err)
					}
				case "permission":
					if err := os.Chmod(path, 0666); err != nil {
						t.Fatal(err)
					}
				case "late_acl":
					if err := unix.Setxattr(path, "system.posix_acl_access", logACL(), 0); err != nil {
						if os.Getenv("ALINKSEC_SHADOW_DEFAULTS_NATIVE_REQUIRED") != "true" && (err == unix.EINVAL || err == unix.EOPNOTSUPP) {
							t.Skip("mandatory native runner must execute ACL change")
						}
						t.Fatal(err)
					}
				case "deadline":
					<-ctx.Done()
				}
				return shadowDefaultsMock(ctx, 0)
			})
			if !result.Error || result.Passed || time.Since(start) > 2*time.Second {
				t.Fatalf("change or deadline must error: %+v", result)
			}
		})
	}
	path := shadowDefaultsFixture(t, "PASS_MAX_DAYS 90\nPASS_WARN_AGE 7\n")
	for _, version := range []string{"", "1:4.15.0-1ubuntu1", "4.13", "1:4.13+dfsg1-4ubuntu3\nDO_NOT_REPORT_SECRET"} {
		result := runShadowDefaults(shadowDefaultsSpec("max_days"), path, func(context.Context, int) ItemResult { return ItemResult{Actual: version} })
		if !result.Error || result.Passed || strings.Contains(result.Actual+result.Message, "DO_NOT_REPORT_SECRET") {
			t.Fatalf("unknown package must error without diagnostic leakage: %+v", result)
		}
	}
}
