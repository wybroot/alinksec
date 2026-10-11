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

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func TestNativeSystemdRescue(t *testing.T) {
	if os.Getenv("ALINKSEC_SYSTEMD_NATIVE_REQUIRED") != "true" {
		t.Skip("explicit disposable systemd runner only")
	}
	if os.Geteuid() != 0 || os.Getenv("ALINKSEC_SYSTEMD_FIXTURES_ALLOWED") != "true" || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Fatal("root and disposable runner authorization required")
	}
	stem := fmt.Sprintf("alinksec-rescue-native-%d", os.Getpid())
	targets := [2]string{stem + ".service", stem + "-emergency.service"}
	paths := [2]string{filepath.Join("/run/systemd/system", targets[0]), filepath.Join("/run/systemd/system", targets[1])}
	for _, path := range paths {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("fixture must not exist")
		}
	}
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("/usr/bin/systemctl", args...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
		if raw, err := cmd.CombinedOutput(); err != nil {
			t.Fatal(args, err, string(raw))
		}
	}
	t.Cleanup(func() {
		for _, path := range paths {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				t.Error(err)
			}
		}
		run("daemon-reload")
	})
	body := func(mode string) string {
		return "[Service]\nType=idle\nEnvironment=HOME=/root PRIVATE_TEST_VALUE=do-not-report-private-value\nExecStart=-/usr/lib/systemd/systemd-sulogin-shell " + mode + "\n"
	}
	write := func(index int, text string) {
		t.Helper()
		if err := os.WriteFile(paths[index], []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		run("daemon-reload")
	}
	cs := rescueSpec()
	cs.TimeoutMs = 5000
	observations := 0
	check := func(name string, want, executionError bool) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		q := rescueQueries{bus: systemMaintenanceQueries(ctx, 5000), cmdline: func() (string, error) { raw, err := os.ReadFile("/proc/cmdline"); return string(raw), err }}
		r := observeRescue(ctx, &cs, targets, q)
		observations++
		t.Logf("native rescue %s: passed=%t error=%t actual=%s message=%s", name, r.Passed, r.Error, r.Actual, r.Message)
		if r.Passed != want || r.Error != executionError || strings.Contains(r.Actual+r.Message, "do-not-report") {
			t.Fatal(name, r)
		}
	}
	check("missing", false, true)
	write(0, body("rescue"))
	write(1, body("emergency"))
	check("both typed launch declarations", true, false)
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/nonexistent/alinksec-rescue-bus")
	t.Setenv("SYSTEMD_UNIT_PATH", "/nonexistent/alinksec-units")
	check("hostile client environment", true, false)
	write(1, body("emergency")+"Environment=SYSTEMD_SULOGIN_FORCE=yes\n")
	check("unit force bypass", false, false)
	write(1, body("emergency")+"Environment=SYSTEMD_SULOGIN_FORCE=no\n")
	check("explicit false", true, false)
	write(1, body("rescue"))
	check("mode mismatch", false, false)
	write(1, "[Service]\nType=idle\nExecStart=/bin/sh -c 'do-not-report-private-value'\n")
	check("shell replacement", false, false)
	write(1, "[Service]\nType=idle\nExecStart=@/usr/lib/systemd/systemd-sulogin-shell \"systemd-sulogin-shell emergency\"\n")
	check("flattened argv spoof", false, false)
	write(1, "[Service]\nType=idle\nExecStart=+/usr/lib/systemd/systemd-sulogin-shell emergency\n")
	check("extended privileged prefix", false, false)
	write(1, body("emergency")+"EnvironmentFile=-/must-not-read-private-env\n")
	check("environment file chain", false, true)
	write(1, body("emergency")+"PassEnvironment=PRIVATE_TEST_VALUE\n")
	check("extra pass environment", false, true)
	write(1, body("emergency")+"UnsetEnvironment=SYSTEMD_SULOGIN_FORCE\n")
	check("extra unset environment", false, true)
	write(1, body("emergency"))
	check("restored", true, false)
	if err := os.WriteFile(paths[1], []byte(body("emergency")+"# pending reload\n"), 0600); err != nil {
		t.Fatal(err)
	}
	check("pending reload", false, true)
	run("daemon-reload")
	check("reloaded", true, false)
	// Independent systemctl representation of these loaded, never-started units.
	for i, target := range targets {
		cmd := exec.Command("/usr/bin/systemctl", "--system", "--no-pager", "show", "--property=Type,ExecStart", "--", target)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
		raw, err := cmd.Output()
		mode := []string{"rescue", "emergency"}[i]
		if err != nil || !strings.Contains(string(raw), "Type=idle") || !strings.Contains(string(raw), "argv[]=/usr/lib/systemd/systemd-sulogin-shell "+mode+" ;") {
			t.Fatal("independent loaded command mismatch", err)
		}
		t.Logf("native rescue independent loaded comparison: mode=%s typed_argv_match=true unit_activations=0", mode)
	}
	t.Run("mandatory_definitions", TestRescueDefinitionBoundary)
	t.Run("mandatory_states_and_redaction", TestRescueLaunchStatesAndRedaction)
	t.Run("mandatory_force_and_typed_bus", TestRescueTypedBusAndForceBoundaries)
	t.Run("mandatory_changes_and_deadline", TestRescueSharedDeadlineChangesAndFailures)
	item := checkOne(&pb.BaselineCheckSpec{ItemId: "rescue-product", Check: rescueJSON()})
	t.Logf("native rescue product read-only observation: item=%s passed=%t error=%t actual=%s message=%s", item.ItemID, item.Passed, item.Error, item.Actual, item.Message)
	if item.ItemID != "rescue-product" {
		t.Fatal(item)
	}
	t.Logf("Native systemd rescue: native_observations=%d mandatory_boundaries_executed=true maintenance_activations=0 password_reads=0", observations)
}
