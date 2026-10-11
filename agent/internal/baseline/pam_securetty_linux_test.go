//go:build linux

package baseline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const secureTTYWriter = "auth [success=1 default=ignore] pam_unix.so\nauth requisite pam_deny.so\nauth required pam_permit.so\n"

func secureTTYFixture(t *testing.T) (pamPaths, string) {
	p := pamFixture(t)
	pamWrite(t, filepath.Join(p.modules, "pam_securetty.so"), "module presence fixture\n")
	pamWrite(t, filepath.Join(p.directory, "login"), "auth required pam_securetty.so noconsole\n"+secureTTYWriter)
	file := filepath.Join(filepath.Dir(p.directory), "securetty")
	pamWrite(t, file, "tty1\ntty2\n")
	return p, file
}

func secureTTYSpec() *CheckSpec {
	return &CheckSpec{Type: "pam_securetty", Target: "/etc/pam.d/login", Operator: "eq", Expected: pamSecureTTYReference, TimeoutMs: 1000}
}

func TestSecureTTYKnownReferencesAndUnknownChains(t *testing.T) {
	for _, tc := range []struct {
		name, gate, list     string
		pass, executionError bool
	}{
		{"reference", "auth required pam_securetty.so noconsole\n", "tty1\ntty2\n", true, false},
		{"requisite", "auth requisite pam_securetty.so noconsole\n", "tty6\n", true, false},
		{"missing_gate", "", "tty1\n", false, false},
		{"console_exception", "auth required pam_securetty.so\n", "tty1\n", false, false},
		{"optional", "auth optional pam_securetty.so noconsole\n", "tty1\n", false, false},
		{"other_terminal", "auth required pam_securetty.so noconsole\n", "pts/8\n", false, false},
		{"empty", "auth required pam_securetty.so noconsole\n", "", false, false},
		{"duplicate", "auth required pam_securetty.so noconsole\n", "tty1\ntty1\n", false, true},
		{"blank", "auth required pam_securetty.so noconsole\n", "tty1\n\n", false, true},
		{"crlf", "auth required pam_securetty.so noconsole\n", "tty1\r\n", false, true},
		{"comment_not_entry", "auth required pam_securetty.so noconsole\n", "#SECRET_TERMINAL\n", false, true},
		{"unknown_arg", "auth required pam_securetty.so SECRET_TERMINAL\n", "tty1\n", false, true},
		{"early_bypass", "auth sufficient pam_permit.so\nauth required pam_securetty.so noconsole\n", "tty1\n", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, file := secureTTYFixture(t)
			pamWrite(t, filepath.Join(p.directory, "login"), tc.gate+secureTTYWriter)
			pamWrite(t, file, tc.list)
			r := pamSecureTTYWithin(secureTTYSpec(), p, file, uint32(os.Geteuid()), uint32(os.Getegid()))
			if r.Passed != tc.pass || r.Error != tc.executionError || strings.Contains(r.Actual+r.Message, "SECRET_TERMINAL") {
				t.Fatal(r)
			}
		})
	}
}

func TestSecureTTYTrustedFilesAndMissingInputs(t *testing.T) {
	for _, kind := range []string{"missing", "symlink", "writable", "unknown_chain"} {
		t.Run(kind, func(t *testing.T) {
			p, file := secureTTYFixture(t)
			switch kind {
			case "missing":
				os.Remove(file)
			case "symlink":
				os.Remove(file)
				os.Symlink(filepath.Join(p.directory, "login"), file)
			case "writable":
				os.Chmod(file, 0666)
			case "unknown_chain":
				pamWrite(t, filepath.Join(p.directory, "login"), "auth required pam_securetty.so noconsole\nauth sufficient pam_sss.so\n")
			}
			r := pamSecureTTYWithin(secureTTYSpec(), p, file, uint32(os.Geteuid()), uint32(os.Getegid()))
			if !r.Error || r.Passed {
				t.Fatal(r)
			}
		})
	}
}
