//go:build linux

package baseline

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestNativeAuditdConfig(t *testing.T) {
	if os.Getenv("ALINKSEC_AUDITD_NATIVE_REQUIRED") != "true" {
		t.Skip("isolated native auditd parser check is opt-in")
	}
	marker, err := os.ReadFile("/usr/local/lib/alinksec-auditd-fixture")
	status, statusErr := os.ReadFile("/proc/self/status")
	if err != nil || string(marker) != "isolated-auditd-config-fixture-v1\n" || os.Geteuid() != 0 || statusErr != nil || !strings.Contains(string(status), "CapEff:\t0000000000000000\n") {
		t.Fatal("disposable container marker, root and all capabilities dropped required")
	}
	version, err := exec.Command("/usr/bin/dpkg-query", "-W", "-f=${Version}", "auditd").CombinedOutput()
	if err != nil || !strings.Contains(string(version), "3.1.2") {
		t.Fatalf("unsupported native auditd version: %s %v", version, err)
	}
	dir := fmt.Sprintf("/var/log/alinksec-auditd-native-%d", os.Getpid())
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	logPath := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(logPath, []byte("PRIVATE_NATIVE_LOG_NO_READ"), 0600); err != nil {
		t.Fatal(err)
	}
	configPath := "/etc/audit/auditd.conf"
	original, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.WriteFile(configPath, original, 0600); err != nil {
			t.Error(err)
		}
	})
	base := auditdBase + "log_file = " + logPath + "\nlog_group = 0\npriority_boost = 0\n"
	for _, test := range []struct {
		name, suffix                      string
		nativeInvalid, agentError, passed bool
	}{
		{"keep_logs", "max_log_file = 8\nmax_log_file_action = keep_logs\n", false, false, true},
		{"rotate is complete noncompliance", "max_log_file = 8\nmax_log_file_action = rotate\n", false, false, false},
		{"write disabled", "write_logs = no\nmax_log_file = 8\nmax_log_file_action = keep_logs\n", false, false, false},
		{"uppercase", "MAX_LOG_FILE = 8\nMAX_LOG_FILE_ACTION = KEEP_LOGS\n", false, false, true},
		{"duplicate native override stays ambiguous", "max_log_file = 8\nmax_log_file_action = keep_logs\nmax_log_file_action = rotate\n", false, true, false},
		{"native skips long line", "max_log_file = 8\nmax_log_file_action = keep_logs\n#" + strings.Repeat("x", 160) + "\n", false, true, false},
		{"native rejects inline comment", "max_log_file_action = keep_logs # comment\n", true, true, false},
		{"native rejects bad flush frequency", "flush = incremental_async\nfreq = 0\n", true, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(configPath, []byte(base+test.suffix), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/usr/sbin/auditd", "-f", "-n", "-s", "nochange", "-c", "/etc/audit")
			cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
			configureBaselineCommand(cmd)
			out, runErr := cmd.CombinedOutput()
			cleanupBaselineCommand(cmd)
			code := 0
			if exit, ok := runErr.(*exec.ExitError); ok {
				code = exit.ExitCode()
			}
			if ctx.Err() != nil || runErr == nil || code != 1 && code != 6 {
				t.Fatalf("unexpected native parser exit %d: %v %s", code, runErr, out)
			}
			if (code == 6) != test.nativeInvalid || !strings.Contains(string(out), "log_file_parser called with:") {
				t.Fatalf("native parser result mismatch %d: %s", code, out)
			}
			if code == 1 && !strings.Contains(string(out), "Operation not permitted") {
				t.Fatalf("expected capability denial after valid configuration: %s", out)
			}
			r := checkAuditdConfig(auditdSpec("keep_logs"))
			if r.Error != test.agentError || r.Passed != test.passed || strings.Contains(r.Actual, "PRIVATE_NATIVE") {
				t.Fatalf("%+v", r)
			}
			t.Logf("native config parse: exit=%d (6=invalid,1=capability denial after parse); agent passed=%t error=%t actual=%s", code, r.Passed, r.Error, r.Actual)
		})
	}
	if err := os.WriteFile(configPath, []byte(base+"max_log_file = 8\nmax_log_file_action = keep_logs\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, option := range []string{"local_logging", "log_file_metadata"} {
		r := checkAuditdConfig(auditdSpec(option))
		if !r.Passed || r.Error {
			t.Fatal(r)
		}
		t.Logf("native filesystem observation: %s", r.Actual)
	}
	if err := os.Chmod(logPath, 0660); err != nil {
		t.Fatal(err)
	}
	if r := checkAuditdConfig(auditdSpec("log_file_metadata")); r.Passed || r.Error {
		t.Fatal(r)
	}
	if err := unix.Setxattr(logPath, "system.posix_acl_access", logACL(), 0); err != nil {
		t.Fatal(err)
	}
	if r := checkAuditdConfig(auditdSpec("log_file_metadata")); !r.Error || r.Passed {
		t.Fatal(r)
	}
}
