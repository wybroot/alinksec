package baseline

import "testing"

func TestApprovedCmdOutputRejectsUnknownCommands(t *testing.T) {
	if len(approvedCmdOutput) != 26 {
		t.Fatalf("approved command count = %d, want 26 seeded commands", len(approvedCmdOutput))
	}
	if !isApprovedCmdOutput("sysctl -n net.ipv4.ip_forward") {
		t.Fatal("seeded baseline command must be approved")
	}
	if isApprovedCmdOutput("sysctl -n net.ipv4.ip_forward; touch /tmp/pwned") {
		t.Fatal("modified command must not be approved")
	}
}
