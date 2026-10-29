package guard

import (
	"os"
	"strings"
	"testing"

	"github.com/shirou/gopsutil/v3/process"
)

func TestTakeForensicsIncludesProcessLineage(t *testing.T) {
	p, err := process.NewProcess(int32(os.Getpid()))
	if err != nil {
		t.Skipf("current process unavailable: %v", err)
	}
	got := takeForensics(p)
	if got == nil || got.Pid != int32(os.Getpid()) {
		t.Fatalf("forensics = %#v, want current process", got)
	}
	if len(got.Lineage) == 0 || got.Lineage[0].Pid != got.Pid {
		t.Fatalf("lineage = %#v, want current process first", got.Lineage)
	}
	if len(got.Lineage) > 8 {
		t.Fatalf("lineage length = %d, want <= 8", len(got.Lineage))
	}
	if len(got.PidTree) != len(got.Lineage) {
		t.Fatalf("pid_tree length = %d, want equal to lineage length %d", len(got.PidTree), len(got.Lineage))
	}
	if got.NetStatus == "" {
		t.Fatal("net_status must not be empty")
	}
}

func TestRedactCommandLineHidesSensitiveArguments(t *testing.T) {
	args := []string{
		"curl", "https://api.example.com",
		"--password", "SuperSecret123",
		"--token=xyz987token",
		"-apiKey", "secretkey456",
		"--user=admin",
	}
	redacted := redactCommandLine(args)
	if redacted == "" {
		t.Fatal("redacted command line must not be empty")
	}
	for _, secret := range []string{"SuperSecret123", "xyz987token", "secretkey456"} {
		if strings.Contains(redacted, secret) {
			t.Fatalf("sensitive token %q leaked in redacted command line: %s", secret, redacted)
		}
	}
	if !strings.Contains(redacted, "***") {
		t.Fatalf("expected *** in redacted output: %s", redacted)
	}
	if !strings.Contains(redacted, "--user=admin") {
		t.Fatalf("expected non-sensitive arg --user=admin preserved: %s", redacted)
	}
}
