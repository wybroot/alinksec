//go:build linux

package baseline

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativePAMAuth(t *testing.T) {
	if os.Getenv("ALINKSEC_PAM_ISOLATED_REQUIRED") != "true" {
		t.Skip("dedicated disposable PAM image required")
	}
	marker, err := os.ReadFile("/usr/local/lib/alinksec-pam-fixture")
	if err != nil || string(marker) != "isolated-pam-fixture-v1\n" || os.Geteuid() != 0 {
		t.Fatal("refuse authentication changes outside the dedicated fixture")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("dedicated container required")
	}
	raw, err := os.ReadFile("../../../deploy/baseline/packages/pam-auth/linux-baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Items []struct{ Check json.RawMessage }
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Items) != 1 {
		t.Fatal("shipped single-item login candidate required")
	}
	spec, err := ParseCheck(string(doc.Items[0].Check))
	if err != nil {
		t.Fatal(err)
	}
	paths := systemPAMAuthPaths()
	password := "F7!jM2@rQ9#vK5%pS8"
	wrong := "incorrect-fixture-token"
	cmd := exec.Command("/usr/sbin/chpasswd", "-c", "SHA512")
	cmd.Stdin = strings.NewReader("root:" + password + "\nalinksec-pam-test:" + password + "\n")
	if err := cmd.Run(); err != nil {
		t.Fatal("isolated credential initialization failed")
	}
	if err := os.MkdirAll("/run/faillock", 0755); err != nil {
		t.Fatal(err)
	}
	configure := func(chain, policy string) {
		t.Helper()
		pamWrite(t, filepath.Join(paths.directory, "login"), "auth include alinksec-auth\n")
		pamWrite(t, filepath.Join(paths.directory, "alinksec-auth"), chain)
		pamWrite(t, paths.policy, policy)
		for _, user := range []string{"root", "alinksec-pam-test"} {
			if err := exec.Command("/usr/sbin/faillock", "--user", user, "--reset").Run(); err != nil {
				t.Fatal("isolated tally reset failed")
			}
		}
	}
	probe := func(user, token string) bool {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/usr/local/bin/alinksec-pam-auth-probe", user)
		cmd.Stdin = strings.NewReader(token + "\n")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("isolated auth probe failed: %v", err)
		}
		result := strings.TrimSpace(string(out))
		if result != "rc=0" && result != "rc=7" {
			t.Fatalf("unexpected public authentication outcome: %s", result)
		}
		return result == "rc=0"
	}
	check := func(pass, executionError bool) ItemResult {
		t.Helper()
		result := pamAuthWithin(spec, paths)
		if result.Passed != pass || result.Error != executionError {
			t.Fatalf("shipped lockout observation: %+v", result)
		}
		return result
	}
	deny := func(user, token string) {
		t.Helper()
		if probe(user, token) {
			t.Fatal("expected isolated authentication denial")
		}
	}
	allow := func(user string) {
		t.Helper()
		if !probe(user, password) {
			t.Fatal("expected isolated authentication success")
		}
	}
	t.Run("consecutive threshold and root lockout", func(t *testing.T) {
		configure(pamAuthChain, pamAuthPolicy+"nodelay\n")
		result := check(true, false)
		for _, user := range []string{"alinksec-pam-test", "root"} {
			allow(user)
			for i := 0; i < 3; i++ {
				deny(user, wrong)
			}
			deny(user, password)
		}
		t.Logf("native PAM auth evidence (isolated Ubuntu24): ordinary/root denied after threshold; %s", result.Actual)
	})
	t.Run("success resets consecutive failures", func(t *testing.T) {
		configure(pamAuthChain, pamAuthPolicy+"nodelay\n")
		check(true, false)
		deny("alinksec-pam-test", wrong)
		deny("alinksec-pam-test", wrong)
		allow("alinksec-pam-test")
		deny("alinksec-pam-test", wrong)
		deny("alinksec-pam-test", wrong)
		allow("alinksec-pam-test")
		t.Log("native PAM auth evidence (isolated Ubuntu24): successful authentication clears earlier failures")
	})
	t.Run("module overrides and explicit SET root flag", func(t *testing.T) {
		chain := strings.ReplaceAll(pamAuthChain, "pam_faillock.so ", "pam_faillock.so deny=2 ")
		configure(chain, strings.ReplaceAll(pamAuthPolicy, "even_deny_root\n", "even_deny_root=0\n")+"deny=5\nnodelay\n")
		result := check(true, false)
		for _, user := range []string{"alinksec-pam-test", "root"} {
			deny(user, wrong)
			deny(user, wrong)
			deny(user, password)
		}
		t.Logf("native PAM auth evidence (isolated Ubuntu24): module threshold overrides file; root SET flag honored; %s", result.Actual)
	})
	t.Run("missing explicit root flag", func(t *testing.T) {
		configure(pamAuthChain, strings.ReplaceAll(strings.ReplaceAll(pamAuthPolicy, "even_deny_root\n", ""), "root_unlock_time=900\n", "")+"nodelay\n")
		check(false, false)
		for i := 0; i < 3; i++ {
			deny("root", wrong)
		}
		allow("root")
		t.Log("native PAM auth evidence (isolated Ubuntu24): root exempt with no explicit root locking settings")
	})
	t.Run("disabled lockout and finite unlock", func(t *testing.T) {
		configure(pamAuthChain, pamAuthPolicy+"deny=0\nnodelay\n")
		check(false, false)
		for i := 0; i < 4; i++ {
			deny("alinksec-pam-test", wrong)
		}
		allow("alinksec-pam-test")
		configure(pamAuthChain, pamAuthPolicy+"deny=1\nunlock_time=2\nroot_unlock_time=2\nnodelay\n")
		check(false, false)
		deny("alinksec-pam-test", wrong)
		deny("alinksec-pam-test", password)
		time.Sleep(3 * time.Second)
		allow("alinksec-pam-test")
		t.Log("native PAM auth evidence (isolated Ubuntu24): deny=0 disables locking; finite unlock restores authentication")
	})
	t.Run("early permit bypass is unconfirmed", func(t *testing.T) {
		configure("auth sufficient pam_permit.so\n"+pamAuthChain, pamAuthPolicy+"nodelay\n")
		check(false, true)
		if !probe("alinksec-pam-test", wrong) {
			t.Fatal("expected observed early permit bypass")
		}
		t.Log("native PAM auth evidence (isolated Ubuntu24): unsupported early permit bypass accepts incorrect token")
	})
	t.Run("inconsistent stage settings are unconfirmed", func(t *testing.T) {
		configure(strings.ReplaceAll(pamAuthChain, "authfail", "authfail deny=1"), pamAuthPolicy+"nodelay\n")
		check(false, true)
		deny("alinksec-pam-test", wrong)
		allow("alinksec-pam-test")
		t.Log("native PAM auth evidence (isolated Ubuntu24): recording-stage threshold alone does not set enforcement threshold")
	})
}
