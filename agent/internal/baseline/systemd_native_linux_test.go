//go:build linux

package baseline

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Opt-in CI runner fixtures use a unique unit only. Never change auditd or
// rsyslog on the host; their actual states are queried separately and recorded.
func TestNativeSystemdService(t *testing.T) {
	if os.Getenv("ALINKSEC_SYSTEMD_NATIVE_REQUIRED") != "true" {
		t.Skip("native systemd runner check is opt-in")
	}
	if os.Getenv("ALINKSEC_SYSTEMD_FIXTURES_ALLOWED") != "true" || os.Geteuid() != 0 {
		t.Fatal("explicit isolated runner fixture authorization and root required")
	}
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("/usr/bin/systemctl", args...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("systemctl %v: %v: %s", args, err, output)
		}
	}
	unit := fmt.Sprintf("alinksec-baseline-native-%d.service", os.Getpid())
	path := filepath.Join("/run/systemd/system", unit)
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("fixture path must not exist")
	}
	t.Cleanup(func() {
		_ = exec.Command("/usr/bin/systemctl", "stop", unit).Run()
		_ = exec.Command("/usr/bin/systemctl", "reset-failed", unit).Run()
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Error(err)
		}
		if output, err := exec.Command("/usr/bin/systemctl", "daemon-reload").CombinedOutput(); err != nil {
			t.Errorf("cleanup reload: %v %s", err, output)
		}
	})
	spec := &CheckSpec{Type: "systemd_service", Target: unit, TimeoutMs: 3000}
	check := func(name string, passed, executionError bool) {
		t.Helper()
		result := checkSystemdService(spec)
		t.Logf("native systemd %s: passed=%t error=%t actual=%s message=%s", name, result.Passed, result.Error, result.Actual, result.Message)
		if result.Passed != passed || result.Error != executionError {
			t.Fatalf("%s: %+v", name, result)
		}
	}
	write := func(contents string) {
		t.Helper()
		if err := os.WriteFile(path, []byte("[Unit]\nDescription=ALinkSec isolated status fixture\n[Service]\n"+contents), 0600); err != nil {
			t.Fatal(err)
		}
		run("daemon-reload")
	}
	check("missing", false, true)
	write("Type=simple\nExecStart=/usr/bin/sleep 120\n")
	check("inactive", false, false)
	run("start", unit)
	// Prove inherited client redirects cannot change the production query.
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/nonexistent/alinksec-test-bus")
	t.Setenv("SYSTEMD_BUS_TIMEOUT", "1us")
	check("running with hostile client environment", true, false)
	run("stop", unit)
	check("stopped", false, false)
	write("Type=oneshot\nExecStart=/usr/bin/true\nRemainAfterExit=yes\n")
	run("start", unit)
	check("active exited is not running", false, false)
	run("stop", unit)
	write("Type=oneshot\nExecStart=/usr/bin/false\n")
	cmd := exec.Command("/usr/bin/systemctl", "start", unit)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	if err := cmd.Run(); err == nil {
		t.Fatal("failed fixture unexpectedly started")
	}
	check("failed", false, false)
	run("reset-failed", unit)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", path); err != nil {
		t.Fatal(err)
	}
	run("daemon-reload")
	check("masked", false, false)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	write("Type=invalid-type\n")
	check("invalid definition", false, true)
	for _, target := range []string{"auditd.service", "rsyslog.service"} {
		result := checkSystemdService(&CheckSpec{Type: "systemd_service", Target: target, TimeoutMs: 3000})
		t.Logf("native product observation: passed=%t error=%t actual=%s message=%s", result.Passed, result.Error, result.Actual, result.Message)
		if !strings.Contains(result.Actual, "unit="+target) {
			t.Fatal("product unit evidence missing")
		}
		if result.Error && !strings.Contains(result.Actual, "LoadState=not-found") {
			t.Fatalf("unexpected product query failure: %+v", result)
		}
		// Actual production names are observations, not required compliant states.
	}
}
