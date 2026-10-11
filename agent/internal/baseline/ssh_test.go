package baseline

import (
	"runtime"
	"testing"
)

func TestSSHOutputRequiresOneValidOption(t *testing.T) {
	for _, tc := range []struct{ output, option, value string }{
		{"permitrootlogin no\nmaxauthtries 3", "permitrootlogin", "no"},
		{"PermitRootLogin prohibit-password", "permitrootlogin", "prohibit-password"},
		{"permitrootlogin without-password", "permitrootlogin", "without-password"},
		{"MaxAuthTries 4", "maxauthtries", "4"},
	} {
		value, err := sshOption(tc.output, tc.option)
		if err != nil || value != tc.value {
			t.Fatalf("output %q: value=%q err=%v", tc.output, value, err)
		}
	}
	for _, tc := range []struct{ output, option string }{
		{"banner none", "permitrootlogin"},
		{"permitrootlogin no\nPermitRootLogin yes", "permitrootlogin"},
		{"permitrootlogin no extra", "permitrootlogin"},
		{"permitrootlogin invalid", "permitrootlogin"},
		{"maxauthtries -1", "maxauthtries"},
		{"maxauthtries 1.5", "maxauthtries"},
		{"maxauthtries 4294967296", "maxauthtries"},
		{"maxauthtries 1", "command"},
	} {
		if _, err := sshOption(tc.output, tc.option); err == nil {
			t.Fatalf("accepted invalid output: %+v", tc)
		}
	}
}

func TestSSHEffectiveDoesNotExecuteOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows platform boundary")
	}
	result := checkSSHEffective(&CheckSpec{Type: "sshd_effective"})
	if !result.Error || result.Passed {
		t.Fatalf("Windows must reject the Linux query: %+v", result)
	}
}
