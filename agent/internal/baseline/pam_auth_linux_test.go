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

const pamAuthChain = "auth required pam_faillock.so preauth silent\nauth [success=1 default=bad] pam_unix.so nodelay\nauth [default=die] pam_faillock.so authfail\nauth sufficient pam_faillock.so authsucc\nauth required pam_deny.so\n"
const pamAuthPolicy = "deny=3\nfail_interval=900\nunlock_time=900\neven_deny_root\nroot_unlock_time=900\n"

func pamAuthFixture(t *testing.T) pamAuthPaths {
	t.Helper()
	p := pamFixture(t)
	paths := pamAuthPaths{p.directory, filepath.Join(filepath.Dir(p.quality), "faillock.conf"), p.modules}
	pamWrite(t, filepath.Join(paths.directory, "login"), "@include common-auth\n")
	pamWrite(t, filepath.Join(paths.directory, "common-auth"), pamAuthChain)
	pamWrite(t, paths.policy, pamAuthPolicy)
	pamWrite(t, filepath.Join(paths.modules, "pam_faillock.so"), "module presence fixture\n")
	return paths
}
func pamAuthSpec() *CheckSpec {
	return &CheckSpec{Type: "pam_auth", Target: "/etc/pam.d/login", Option: "faillock", Operator: "eq", Expected: pamLockoutReference, TimeoutMs: 1000}
}
func pamAuthResult(t *testing.T, paths pamAuthPaths) ItemResult {
	t.Helper()
	result := pamAuthWithin(pamAuthSpec(), paths)
	if strings.Contains(result.Actual+result.Message, "DO_NOT_REPORT_PAM_SECRET") {
		t.Fatal("unknown input escaped into evidence")
	}
	return result
}

func TestPAMAuthConfigurationOrderIncludesAndRootSETFlag(t *testing.T) {
	paths := pamAuthFixture(t)
	pamWrite(t, filepath.Join(paths.directory, "login"), "auth include nested\npassword required not-in-auth.so\n")
	pamWrite(t, filepath.Join(paths.directory, "nested"), "@include common-auth\n")
	pamWrite(t, paths.policy, pamAuthPolicy+"deny = 5\neven_deny_root=0\n")
	chain := strings.ReplaceAll(pamAuthChain, "pam_faillock.so ", "pam_faillock.so deny=2 unlock_time=1800 root_unlock_time=1800 ")
	chain = strings.Replace(chain, "auth required", "AUTH required", 1)
	chain = strings.Replace(chain, "preauth silent", "preauth \\\n silent", 1)
	pamWrite(t, filepath.Join(paths.directory, "common-auth"), chain)
	result := pamAuthResult(t, paths)
	if result.Error || !result.Passed || !strings.Contains(result.Actual, "deny=2") || !strings.Contains(result.Actual, "explicit_even_deny_root=true root_unlock_time=1800") {
		t.Fatalf("lost order or SET semantics: %+v", result)
	}
	pamWrite(t, paths.policy, strings.ReplaceAll(pamAuthPolicy, "root_unlock_time=900\n", ""))
	pamWrite(t, filepath.Join(paths.directory, "common-auth"), strings.ReplaceAll(pamAuthChain, "pam_faillock.so ", "pam_faillock.so unlock_time=1200 "))
	if result := pamAuthResult(t, paths); result.Error || !result.Passed || !strings.Contains(result.Actual, "root_unlock_time=1200") {
		t.Fatalf("root inherits final module unlock_time: %+v", result)
	}
}

func TestPAMAuthSeparatesReferenceFailuresFromUnknownChains(t *testing.T) {
	for _, change := range []string{"deny=0\n", "deny=6\n", "fail_interval=899\n", "unlock_time=0\n", "unlock_time=never\n", "unlock_time=899\n", "unlock_time=86401\n", "root_unlock_time=0\n", "root_unlock_time=86401\n"} {
		paths := pamAuthFixture(t)
		pamWrite(t, paths.policy, pamAuthPolicy+change)
		if result := pamAuthResult(t, paths); result.Error || result.Passed {
			t.Fatalf("known reference mismatch %q: %+v", change, result)
		}
	}
	paths := pamAuthFixture(t)
	pamWrite(t, paths.policy, strings.ReplaceAll(pamAuthPolicy, "even_deny_root\n", ""))
	if result := pamAuthResult(t, paths); result.Error || result.Passed {
		t.Fatalf("missing explicit root flag: %+v", result)
	}
	pamWrite(t, filepath.Join(paths.directory, "common-auth"), strings.ReplaceAll(strings.ReplaceAll(pamWriter, "password ", "auth "), "obscure yescrypt use_authtok", "nullok"))
	if result := pamAuthResult(t, paths); result.Error || result.Passed || !strings.Contains(result.Actual, "faillock_present=false") {
		t.Fatalf("understood absent lockout: %+v", result)
	}
	for _, chain := range []string{
		"auth sufficient pam_permit.so\n" + pamAuthChain,
		strings.ReplaceAll(pamAuthChain, "success=1", "success=2"),
		strings.ReplaceAll(pamAuthChain, "default=die", "default=ignore"),
		strings.ReplaceAll(pamAuthChain, "preauth silent", "authsucc silent"),
		strings.ReplaceAll(pamAuthChain, "authfail", "authfail deny=4"),
		strings.ReplaceAll(pamAuthChain, "authfail", "authfail dir=/run/faillock"),
		strings.ReplaceAll(pamAuthChain, "authsucc", "authsucc conf=/tmp/DO_NOT_REPORT_PAM_SECRET"),
		strings.ReplaceAll(pamAuthChain, "preauth silent", "preauth authfail"),
		strings.ReplaceAll(pamAuthChain, "preauth silent", "preauth deny=3 deny=3"),
		strings.ReplaceAll(pamAuthChain, "pam_unix.so", "pam_sss.so"),
		strings.ReplaceAll(pamAuthChain, "pam_unix.so", "/tmp/pam_unix.so"),
		"auth substack common-auth\n",
		"auth include ../DO_NOT_REPORT_PAM_SECRET\n",
		"@include login\n",
	} {
		paths := pamAuthFixture(t)
		pamWrite(t, filepath.Join(paths.directory, "common-auth"), chain)
		if result := pamAuthResult(t, paths); !result.Error || result.Passed {
			t.Fatalf("unconfirmed chain accepted %q: %+v", chain, result)
		}
	}
}

func TestPAMAuthRejectsInvalidConfigAndUnsafeInputs(t *testing.T) {
	for _, change := range []string{"deny=-1\n", "deny=65536\n", "deny=3junk\n", "unlock_time=604801\n", "deny=\n", "admin_group=DO_NOT_REPORT_PAM_SECRET\n", "dir=/tmp/DO_NOT_REPORT_PAM_SECRET\n", "local_users_only\n", "DENY=2\n", "unknown=DO_NOT_REPORT_PAM_SECRET\n", strings.Repeat("x", 1023) + "\n"} {
		paths := pamAuthFixture(t)
		pamWrite(t, paths.policy, pamAuthPolicy+change)
		if result := pamAuthResult(t, paths); !result.Error || result.Passed {
			t.Fatalf("invalid policy %q: %+v", change, result)
		}
	}
	for _, kind := range []string{"missing", "link", "directory", "fifo", "oversize", "module"} {
		paths := pamAuthFixture(t)
		if err := os.Remove(paths.policy); err != nil {
			t.Fatal(err)
		}
		switch kind {
		case "link":
			if err := os.Symlink(filepath.Join(paths.directory, "login"), paths.policy); err != nil {
				t.Fatal(err)
			}
		case "directory":
			if err := os.Mkdir(paths.policy, 0700); err != nil {
				t.Fatal(err)
			}
		case "fifo":
			if err := unix.Mkfifo(paths.policy, 0600); err != nil {
				t.Fatal(err)
			}
		case "oversize":
			pamWrite(t, paths.policy, strings.Repeat("#", 65537))
		case "module":
			pamWrite(t, paths.policy, pamAuthPolicy)
			if err := os.Remove(filepath.Join(paths.modules, "pam_faillock.so")); err != nil {
				t.Fatal(err)
			}
		}
		if result := pamAuthResult(t, paths); !result.Error || result.Passed {
			t.Fatalf("unsafe input %s: %+v", kind, result)
		}
	}
	paths := pamAuthFixture(t)
	r := newPAMRead(1000)
	defer r.close()
	if _, err := readFaillockSettings(r, paths.policy); err != nil {
		t.Fatal(err)
	}
	pamWrite(t, paths.policy, pamAuthPolicy+"deny=4\n")
	if err := r.stable(); err == nil {
		t.Fatal("changed input accepted")
	}
	r.deadline = time.Now().Add(-time.Second)
	if err := r.budget(); err == nil {
		t.Fatal("expired read accepted")
	}
}
