//go:build linux

package baseline

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func TestNativeSystemdMaintenance(t *testing.T) {
	if os.Getenv("ALINKSEC_SYSTEMD_NATIVE_REQUIRED") != "true" {
		t.Skip("explicit disposable systemd runner only")
	}
	if os.Geteuid() != 0 || os.Getenv("ALINKSEC_SYSTEMD_FIXTURES_ALLOWED") != "true" || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Fatal("root and disposable runner authorization required")
	}
	stem := fmt.Sprintf("alinksec-maint-native-%d", os.Getpid())
	targets := maintenanceTargets{stem + ".timer", stem + ".service", stem + "-clock.service"}
	paths := []string{filepath.Join("/run/systemd/system", targets.timer), filepath.Join("/run/systemd/system", targets.cleaner), filepath.Join("/run/systemd/system", targets.sync)}
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
		for _, unit := range []string{targets.timer, targets.cleaner, targets.sync} {
			exec.Command("/usr/bin/systemctl", "stop", unit).Run()
			exec.Command("/usr/bin/systemctl", "reset-failed", unit).Run()
		}
		for _, path := range paths {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				t.Error(err)
			}
		}
		run("daemon-reload")
	})
	write := func(index int, body string) {
		t.Helper()
		if err := os.WriteFile(paths[index], []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		run("daemon-reload")
	}
	cs := maintenanceSpec("tmpfiles_clean")
	cs.TimeoutMs = 5000
	observations := 0
	check := func(name string, want, errorWant bool) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		r := observeMaintenance(ctx, &cs, targets, systemMaintenanceQueries(ctx, 5000))
		t.Logf("native maintenance %s: passed=%t error=%t actual=%s message=%s", name, r.Passed, r.Error, r.Actual, r.Message)
		observations++
		if r.Passed != want || r.Error != errorWant {
			t.Fatal(name, r)
		}
	}
	check("missing", false, true)
	// No real cleanup job is started. The unique timer is six hours in the future
	// and is stopped/removed within this test's 120-second process budget.
	cleaner := "[Service]\nType=oneshot\nExecStart=/usr/bin/systemd-tmpfiles --clean\n"
	timer := "[Timer]\nOnActiveSec=6h\nUnit=" + targets.cleaner + "\n"
	write(1, cleaner)
	write(0, timer)
	check("inactive timer", false, false)
	run("start", targets.timer)
	check("waiting complete typed command", true, false)
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/nonexistent/alinksec-maint-bus")
	t.Setenv("SYSTEMD_UNIT_PATH", "/nonexistent/alinksec-units")
	check("hostile client environment", true, false)
	write(0, "[Timer]\nOnActiveSec=6h\nUnit="+stem+"-other.service\n")
	check("wrong cleanup target", false, false)
	write(0, timer)
	write(1, cleaner+"RemainAfterExit=yes\n")
	check("remain after exit", false, false)
	write(1, "[Service]\nType=oneshot\nExecStart=/usr/bin/true must-not-report-secret\n")
	check("other command", false, false)
	write(1, "[Service]\nType=oneshot\nExecStart=@/usr/bin/systemd-tmpfiles \"systemd-tmpfiles --clean\"\n")
	check("flattened argv spoof", false, false)
	write(1, cleaner)
	check("restored command", true, false)
	if err := os.WriteFile(paths[0], []byte(timer+"# retained pending reload\n"), 0600); err != nil {
		t.Fatal(err)
	}
	check("pending reload", false, true)
	run("daemon-reload")
	check("reloaded timer", true, false)
	run("stop", targets.timer)
	check("stopped timer", false, false)

	// A harmless running service cannot impersonate timesyncd merely by its name.
	// This exercises the real system manager and typed ExecStart without starting
	// any clock daemon or changing the host clock.
	write(2, "[Service]\nType=notify\nNotifyAccess=all\nExecStart=/bin/sh -c 'systemd-notify --ready; exec /usr/bin/sleep 120'\n")
	run("start", targets.sync)
	cs = maintenanceSpec("time_sync")
	cs.TimeoutMs = 5000
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	q := systemMaintenanceQueries(ctx, 5000)
	q.clock = func() (kernelClockSample, error) { return kernelClockSample{0, 0x2001, 100, 100}, nil }
	r := observeMaintenance(ctx, &cs, targets, q)
	cancel()
	observations++
	t.Logf("native maintenance running wrong time program: passed=%t error=%t actual=%s", r.Passed, r.Error, r.Actual)
	if r.Passed || r.Error {
		t.Fatal(r)
	}

	goClock, err := readKernelClock()
	if err != nil {
		t.Fatal(err)
	}
	probe := os.Getenv("ALINKSEC_CLOCK_READONLY_PROBE")
	if probe == "" {
		t.Fatal("mandatory independent read-only C clock probe required")
	}
	output, err := exec.Command(probe).Output()
	if err != nil {
		t.Fatal(err)
	}
	values := strings.Fields(string(output))
	if len(values) != 4 {
		t.Fatal(string(output))
	}
	state, e := strconv.Atoi(values[0])
	if e != nil || state < 0 || state > 5 {
		t.Fatal(string(output))
	}
	status, e := strconv.ParseUint(values[1], 10, 32)
	if e != nil || status > 0xffff {
		t.Fatal(string(output))
	}
	afterClock, e := readKernelClock()
	if e != nil {
		t.Fatal(e)
	}
	if goClock.State == afterClock.State && goClock.Status == afterClock.Status && (state != goClock.State || uint32(status) != goClock.Status) {
		t.Fatal("independent native clock ABI mismatch during stable observation", goClock, afterClock, string(output))
	}
	// Estimates and flags can change between independent samples; neither sample
	// is used to certify offset accuracy or the identity of an NTP provider.
	t.Logf("native kernel clock readonly ABI evidence: go_state=%d go_status=0x%x c_state=%d c_status=0x%x", goClock.State, goClock.Status, state, status)
	if goClock.State < 0 || goClock.State > 5 || goClock.Status > 0xffff {
		t.Fatal(goClock)
	}
	t.Run("mandatory_typed_bus_and_argv", TestMaintenanceTypedBusPreservesArgumentsAndRejectsMalformedData)
	t.Run("mandatory_states_and_boundaries", TestMaintenanceSeparatesStatesFromDelivery)
	t.Run("mandatory_changes_and_deadline", TestMaintenanceSharedDeadlineAndChanges)

	for _, option := range []string{"tmpfiles_clean", "time_sync"} {
		s := maintenanceSpec(option)
		s.TimeoutMs = 5000
		item := checkOne(&pb.BaselineCheckSpec{ItemId: "maintenance-product-" + option, Check: maintenanceJSON(s)})
		t.Logf("native maintenance product read-only observation: item=%s passed=%t error=%t actual=%s message=%s", item.ItemID, item.Passed, item.Error, item.Actual, item.Message)
		if item.ItemID != "maintenance-product-"+option {
			t.Fatal(item)
		}
	}
	t.Logf("Native systemd maintenance: native_observations=%d mandatory_boundaries_executed=true clock_write_calls=0 real_cleanup_activations=0", observations)
}
