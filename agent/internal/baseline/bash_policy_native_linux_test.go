//go:build linux

package baseline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestNativeBashGlobalPolicy(t *testing.T) {
	if os.Getenv("ALINKSEC_BASH_NATIVE_REQUIRED") != "true" {
		t.Skip("explicit disposable Ubuntu24 Bash fixture only")
	}
	marker, err := os.ReadFile("/usr/local/lib/alinksec-pam-fixture")
	if os.Geteuid() != 0 || os.Getenv("ALINKSEC_BASH_ISOLATED_REQUIRED") != "true" || err != nil || string(marker) != "isolated-pam-fixture-v1\n" {
		t.Fatal("root, both switches and isolated marker required; refusing to alter host startup")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	versions := queryBashPolicyVersions(ctx, 5000)
	cancel()
	if versions.Error || !bashInstalledVersions.MatchString(versions.Actual) {
		t.Fatal("exact installed Ubuntu24 Bash/base-files required")
	}
	paths := systemBashPolicyPaths()
	profile, err := os.ReadFile("/etc/profile")
	if err != nil {
		t.Fatal(err)
	}
	rc, err := os.ReadFile("/etc/bash.bashrc")
	if err != nil {
		t.Fatal(err)
	}
	// The original prefix is checked by the production selector before any fixture
	// rewrite. Distribution variants fail explicitly instead of being guessed.
	signature := func(raw []byte, p bashVendorPrefix) bool {
		return len(raw) >= p.bytes && fmt.Sprintf("%x", sha256.Sum256(raw[:p.bytes])) == p.sha256
	}
	if !signature(profile, paths.profile) || !signature(rc, paths.bashrc) {
		t.Fatalf("unrecognized isolated vendor prefixes: profile_bytes=%d bashrc_bytes=%d", len(profile), len(rc))
	}
	if err := os.Rename("/etc/profile.d", "/etc/alinksec-bash-original-profile.d"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir("/etc/profile.d", 0755); err != nil {
		t.Fatal(err)
	}
	restored := false
	restore := func() error {
		if restored {
			return nil
		}
		if err := os.WriteFile("/etc/profile", profile, 0644); err != nil {
			return err
		}
		if err := os.WriteFile("/etc/bash.bashrc", rc, 0644); err != nil {
			return err
		}
		if err := os.RemoveAll("/etc/profile.d"); err != nil {
			return err
		}
		if err := os.Rename("/etc/alinksec-bash-original-profile.d", "/etc/profile.d"); err != nil {
			return err
		}
		restored = true
		return nil
	}
	t.Cleanup(func() {
		if err := restore(); err != nil {
			t.Error(err)
		}
	})

	for _, name := range []string{".bash_profile", ".bashrc", ".bash_logout"} {
		file := filepath.Join("/root", name)
		raw, readErr := os.ReadFile(file)
		if readErr != nil && !os.IsNotExist(readErr) {
			t.Fatal(readErr)
		}
		if err := os.WriteFile(file, nil, 0600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if readErr == nil {
				os.WriteFile(file, raw, 0600)
			} else {
				os.Remove(file)
			}
		})
	}
	originalMask := unix.Umask(0022)
	defer unix.Umask(originalMask)
	good := "export TMOUT=600\nreadonly TMOUT\numask 027\nHISTTIMEFORMAT='%F %T %z '\nHISTSIZE=1000\nHISTFILESIZE=1000\n"
	type expectation struct {
		tmout, loginMask, nonloginMask, format, size, fileSize string
		readonly, exported                                     bool
	}
	cases := []struct {
		name, rc, tail string
		parts          map[string]string
		uid            uint32
		want           expectation
		pass           [5]bool
	}{
		{"root_approved", good, "", nil, 0, expectation{"600", "027", "027", "%F %T %z ", "1000", "1000", true, true}, [5]bool{true, true, true, true, true}},
		{"ordinary_approved", good, "", nil, 65534, expectation{"600", "027", "027", "%F %T %z ", "1000", "1000", true, true}, [5]bool{true, true, true, true, true}},
		{"absent_defaults", "", "", nil, 0, expectation{"absent", "022", "022", "absent", "500", "500", false, false}, [5]bool{}},
		{"sorted_overrides", "TMOUT=0\numask 022\nHISTSIZE=1000\nHISTFILESIZE=1000\n", "umask 027\n", map[string]string{"90-final.sh": "export TMOUT=600\nreadonly TMOUT\numask 077\nHISTTIMEFORMAT='%F %T %z '\nHISTSIZE=2000\nHISTFILESIZE=2000\n", "10-first.sh": "TMOUT=100\numask 000\n"}, 0, expectation{"600", "027", "022", "%F %T %z ", "2000", "2000", true, true}, [5]bool{true, true, true, true, false}},
		{"login_nonlogin_distinction", strings.ReplaceAll(good, "umask 027", "umask 022"), "", map[string]string{"policy.sh": "umask 077\n"}, 0, expectation{"600", "077", "022", "%F %T %z ", "1000", "1000", true, true}, [5]bool{true, true, true, true, false}},
		{"timeout_not_protected", strings.ReplaceAll(good, "readonly TMOUT\n", ""), "", nil, 0, expectation{"600", "027", "027", "%F %T %z ", "1000", "1000", false, true}, [5]bool{false, true, true, true, true}},
		{"history_disabled", strings.ReplaceAll(strings.ReplaceAll(good, "HISTSIZE=1000", "HISTSIZE=0"), "HISTFILESIZE=1000", "HISTFILESIZE=-1"), "", nil, 0, expectation{"600", "027", "027", "%F %T %z ", "0", "-1", true, true}, [5]bool{true, true, true, false, true}},
		{"history_format_mismatch", strings.ReplaceAll(good, "%F %T %z ", "%F"), "", nil, 0, expectation{"600", "027", "027", "%F", "1000", "1000", true, true}, [5]bool{true, true, false, true, true}},
	}
	comparisons := 0
	options := []string{"login_timeout", "login_umask", "history_time", "history_capacity", "nonlogin_umask"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile("/etc/profile", append(append([]byte{}, profile[:paths.profile.bytes]...), []byte(tc.tail)...), 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile("/etc/bash.bashrc", append(append([]byte{}, rc[:paths.bashrc.bytes]...), []byte(tc.rc)...), 0644); err != nil {
				t.Fatal(err)
			}
			entries, err := os.ReadDir("/etc/profile.d")
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if err := os.Remove(filepath.Join("/etc/profile.d", entry.Name())); err != nil {
					t.Fatal(err)
				}
			}
			for name, body := range tc.parts {
				if err := os.WriteFile(filepath.Join("/etc/profile.d", name), []byte(body), 0644); err != nil {
					t.Fatal(err)
				}
			}
			native := func(login bool) []string {
				script := `printf 'ALINKSEC_NATIVE\t%s\t%s\t%s\t%s\t%s\n' "${TMOUT-absent}" "$(umask)" "${HISTTIMEFORMAT-absent}" "${HISTSIZE-absent}" "${HISTFILESIZE-absent}"; printf 'ALINKSEC_ATTRIBUTES\t'; declare -p TMOUT 2>/dev/null || :`
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				flag := "-ic"
				if login {
					flag = "-lic"
				}
				cmd := exec.CommandContext(ctx, "/bin/bash", flag, script)
				cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "TERM=dumb", "TZ=UTC"}
				cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: tc.uid, Gid: tc.uid}}
				var stdout, stderr bytes.Buffer
				cmd.Stdout = &stdout
				cmd.Stderr = &stderr
				if err := cmd.Run(); err != nil || strings.Contains(stderr.String(), "readonly variable") {
					t.Fatal("controlled native Bash startup failed")
				}
				var fields []string
				attributes := ""
				for _, line := range strings.Split(stdout.String(), "\n") {
					if strings.HasPrefix(line, "ALINKSEC_NATIVE\t") {
						fields = strings.Split(line, "\t")[1:]
					}
					if strings.HasPrefix(line, "ALINKSEC_ATTRIBUTES\t") {
						attributes = strings.TrimPrefix(line, "ALINKSEC_ATTRIBUTES\t")
					}
				}
				if len(fields) != 5 {
					t.Fatal("native evidence incomplete")
				}
				mask, err := strconv.ParseUint(fields[1], 8, 16)
				if err != nil {
					t.Fatal("native umask invalid")
				}
				fields[1] = fmt.Sprintf("%03o", mask)
				if login {
					expected := []string{tc.want.tmout, tc.want.loginMask, tc.want.format, tc.want.size, tc.want.fileSize}
					for i := range expected {
						if fields[i] != expected[i] {
							t.Fatalf("native field index=%d differs from controlled fixture", i)
						}
					}
					ro := strings.Contains(attributes, "-r")
					ex := strings.Contains(attributes, "-x") || strings.Contains(attributes, "rx")
					if ro != tc.want.readonly || ex != tc.want.exported {
						t.Fatal("native readonly/export attributes differ")
					}
				} else if fields[1] != tc.want.nonloginMask {
					t.Fatal("native nonlogin mask differs")
				}
				return fields
			}
			loginFields, nonloginFields := native(true), native(false)
			for i, option := range options {
				s := bashPolicySpec(option)
				result := checkBashGlobalPolicy(&s)
				if result.Error || result.Passed != tc.pass[i] {
					t.Fatalf("%s: %+v", option, result)
				}
				comparisons++
				t.Logf("native Bash global declaration evidence: case=%s option=%s native_login_tmout=%s native_login_umask=%s native_nonlogin_umask=%s passed=%t actual=%s", tc.name, option, loginFields[0], loginFields[1], nonloginFields[1], result.Passed, result.Actual)
			}
		})
	}
	t.Run("mandatory_trust_syntax_changes_and_deadline", func(t *testing.T) {
		t.Run("finite_declarations", TestBashFiniteDeclarationSemantics)
		t.Run("startup_ordering", TestBashStartupOrderingAndScope)
		t.Run("finite_inputs", TestBashStartupFiniteInputsAndLimits)
		t.Run("unsafe_inputs", TestBashStartupUnsafeInputs)
		t.Run("changes_and_deadline", TestBashStartupChangesAndOneDeadline)
	})
	if comparisons != 40 {
		t.Fatalf("mandatory comparisons=%d", comparisons)
	}
	if err := restore(); err != nil {
		t.Fatal(err)
	}
	result := checkOne(&pb.BaselineCheckSpec{ItemId: "bash-global-product", Check: bashPolicyJSON(bashPolicySpec("login_umask"))})
	if result.ItemID != "bash-global-product" {
		t.Fatal("dispatcher lost item identity")
	}
	t.Logf("native Bash read-only fixed selector observation: item=%s passed=%t error=%t actual=%s", result.ItemID, result.Passed, result.Error, result.Actual)
	t.Logf("Native Bash global declarations: scenarios=9 native_comparisons=%d mandatory_boundaries_executed=true", comparisons)
}
