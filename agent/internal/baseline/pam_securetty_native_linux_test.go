//go:build linux

package baseline

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativePAMSecureTTY(t *testing.T) {
	if os.Getenv("ALINKSEC_PAM_ISOLATED_REQUIRED") != "true" {
		t.Skip("dedicated isolated PAM image required")
	}
	marker, err := os.ReadFile("/usr/local/lib/alinksec-pam-fixture")
	if err != nil || string(marker) != "isolated-pam-fixture-v1\n" || os.Geteuid() != 0 {
		t.Fatal("isolated PAM marker and root required")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("dedicated disposable container required")
	}
	p := systemPAMPaths()
	password := "T7^pN5@qR9!vS2#mL6"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	set := exec.CommandContext(ctx, "/usr/sbin/chpasswd")
	set.Stdin = strings.NewReader("root:" + password + "\nalinksec-pam-test:" + password + "\n")
	if err := set.Run(); err != nil {
		t.Fatal("isolated account fixture failed")
	}
	configure := func(gate, list string) {
		pamWrite(t, filepath.Join(p.directory, "login"), gate+secureTTYWriter)
		pamWrite(t, "/etc/securetty", list)
	}
	observe := func(pass, executionError bool) {
		r := checkPAMSecureTTY(secureTTYSpec())
		if r.Passed != pass || r.Error != executionError || strings.Contains(r.Actual+r.Message, password) {
			t.Fatal(r)
		}
	}
	probe := func(user, tty string, want bool) {
		cmd := exec.CommandContext(ctx, "/usr/local/bin/alinksec-pam-auth-probe", user, tty)
		cmd.Stdin = strings.NewReader(password + "\n")
		out, err := cmd.Output()
		if err != nil || strings.Contains(string(out), password) || (strings.TrimSpace(string(out)) == "rc=0") != want {
			t.Fatal("isolated native terminal outcome mismatch")
		}
	}
	gate := "auth required pam_securetty.so noconsole\n"
	configure(gate, "tty1\ntty6\n")
	observe(true, false)
	probe("root", "tty1", true)
	probe("root", "/dev/tty1", true)
	probe("root", "pts/8", false)
	probe("alinksec-pam-test", "pts/8", true)
	configure("auth optional pam_securetty.so noconsole\n", "tty1\n")
	observe(false, false)
	probe("root", "pts/8", true)
	configure(gate, "tty9\n")
	observe(false, false)
	probe("root", "tty9", true)
	configure(gate, "")
	observe(false, false)
	probe("root", "tty1", false)
	os.Remove("/etc/securetty")
	observe(false, true)
	probe("root", "pts/8", true)
	configure("auth sufficient pam_permit.so\n"+gate, "tty1\n")
	observe(false, true)
	probe("root", "pts/8", true)
	t.Run("mandatory_definition", TestSecureTTYDefinitionBoundary)
	t.Run("mandatory_states", TestSecureTTYKnownReferencesAndUnknownChains)
	t.Run("mandatory_inputs", TestSecureTTYTrustedFilesAndMissingInputs)
	t.Log("Native securetty: configuration_observations=6 authentication_comparisons=9 mandatory_boundaries_executed=true host_authentication_changes=0 credential_output=0")
}
