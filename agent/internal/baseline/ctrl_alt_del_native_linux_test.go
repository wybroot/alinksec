//go:build linux

package baseline

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

// Only disposable Ubuntu24 CI runners may change this unique harmless target
// and a unique runtime manager drop-in. Never start ctrl-alt-del/reboot targets,
// send SIGINT, simulate keyboard events or change a persistent configuration.
func TestNativeSystemdCtrlAltDel(t *testing.T) {
	if os.Getenv("ALINKSEC_SYSTEMD_NATIVE_REQUIRED") != "true" {
		t.Skip("native systemd runner check is opt-in")
	}
	if os.Getenv("ALINKSEC_SYSTEMD_FIXTURES_ALLOWED") != "true" || os.Geteuid() != 0 || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Fatal("disposable GitHub-hosted runner fixture authorization and root required")
	}
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("/usr/bin/systemctl", args...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("systemctl %v: %v: %s", args, err, output)
		}
		return strings.TrimSpace(string(output))
	}
	originalBurst := run("--system", "show", "--property=CtrlAltDelBurstAction", "--value")
	unit := fmt.Sprintf("alinksec-cad-native-%d.target", os.Getpid())
	path := filepath.Join("/run/systemd/system", unit)
	dir := "/run/systemd/system.conf.d"
	dropin := filepath.Join(dir, fmt.Sprintf("zz-alinksec-cad-native-%d.conf", os.Getpid()))
	for _, candidate := range []string{path, dropin} {
		if _, err := os.Lstat(candidate); !os.IsNotExist(err) {
			t.Fatal("fixture path must not exist")
		}
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = exec.Command("/usr/bin/systemctl", "stop", unit).Run()
		for _, candidate := range []string{path, dropin} {
			if err := os.Remove(candidate); err != nil && !os.IsNotExist(err) {
				t.Error(err)
			}
		}
		run("daemon-reload")
		if actual := run("--system", "show", "--property=CtrlAltDelBurstAction", "--value"); actual != originalBurst {
			t.Errorf("manager burst setting not restored: %s != %s", actual, originalBurst)
		}
	})
	setBurst := func(action string) {
		t.Helper()
		if err := os.WriteFile(dropin, []byte("[Manager]\nCtrlAltDelBurstAction="+action+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		run("daemon-reload")
		if actual := run("--system", "show", "--property=CtrlAltDelBurstAction", "--value"); actual != action {
			t.Fatalf("isolated runtime burst setting did not load: %s", actual)
		}
	}
	spec := &CheckSpec{Type: "systemd_ctrl_alt_del", Target: unit, TimeoutMs: 5000}
	check := func(name string, passed, executionError bool) {
		t.Helper()
		result := checkCtrlAltDel(spec)
		t.Logf("native Ctrl-Alt-Del %s: passed=%t error=%t actual=%s message=%s", name, result.Passed, result.Error, result.Actual, result.Message)
		if result.Passed != passed || result.Error != executionError {
			t.Fatalf("%s: %+v", name, result)
		}
	}
	setBurst("none")
	check("missing target", false, true)
	contents := "[Unit]\nDescription=ALinkSec harmless isolated target\nDefaultDependencies=no\n[Install]\nWantedBy=multi-user.target\n"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	run("daemon-reload")
	check("disabled target remains loadable", false, false)
	run("start", unit)
	check("active target", false, false)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", path); err != nil {
		t.Fatal(err)
	}
	run("daemon-reload")
	check("mask does not stop active target", false, false)
	run("stop", unit)
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/nonexistent/alinksec-test-bus")
	t.Setenv("SYSTEMD_BUS_TIMEOUT", "1us")
	t.Setenv("SYSTEMD_UNIT_PATH", "/nonexistent/alinksec-unit-path")
	check("runtime mask and disabled burst with hostile environment", true, false)
	for _, action := range []string{"reboot-force", "reboot-immediate", "poweroff-force", "poweroff-immediate"} {
		setBurst(action)
		check("mask with loaded burst "+action, false, false)
	}
	setBurst("none")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	// The cached mask must not produce pass when its on-disk definition changes.
	check("mask replaced without reload", false, true)
	run("daemon-reload")
	check("unmasked after reload", false, false)
	// Restore before observing the real special target. It is never modified.
	if err := os.Remove(dropin); err != nil {
		t.Fatal(err)
	}
	run("daemon-reload")
	result := Run("cad-native", []*pb.BaselineCheckSpec{{ItemId: "6060", Check: `{"type":"systemd_ctrl_alt_del","target":"ctrl-alt-del.target","operator":"eq","expected":"masked/inactive/dead,burst_action=none","timeout_ms":5000}`}}, slog.New(slog.NewTextHandler(io.Discard, nil))).Items[0]
	t.Logf("native real special target read-only observation: %+v", result)
	if result.ItemId != "6060" || result.ExecutionStatus == "error" || !strings.Contains(result.Actual, "CtrlAltDelBurstAction="+originalBurst) {
		t.Fatalf("real special target query/dispatch failed: %+v", result)
	}
}
