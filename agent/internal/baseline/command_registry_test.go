package baseline

import (
	"runtime"
	"testing"
)

func TestApprovedCmdOutputRejectsUnknownCommands(t *testing.T) {
	want := 26
	if runtime.GOOS == "windows" {
		want = 4
	}
	if len(approvedCmdOutput) != want {
		t.Fatalf("approved command count = %d, want %d", len(approvedCmdOutput), want)
	}
	if runtime.GOOS == "linux" && !isApprovedCmdOutput("sysctl -n net.ipv4.ip_forward") {
		t.Fatal("seeded baseline command must be approved")
	}
	if isApprovedCmdOutput("sysctl -n net.ipv4.ip_forward; touch /tmp/pwned") {
		t.Fatal("modified command must not be approved")
	}
}
