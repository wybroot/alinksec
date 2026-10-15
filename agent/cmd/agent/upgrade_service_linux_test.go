//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

type systemdUpgradeService struct{}

func testSystemctl(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("systemctl %v: %v\n%s", args, err, b)
	}
	return strings.TrimSpace(string(b))
}
func testUnitArg(s string) string {
	return "\"" + strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "%", "%%").Replace(s) + "\""
}
func newUpgradeTestService(t *testing.T, binary, work string) upgradeTestService {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("native systemd upgrade fixture requires root")
	}
	for _, name := range []string{"alinksec-agent", "alinksec-agent-upgrade-watchdog"} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		b, _ := exec.CommandContext(ctx, "systemctl", "show", "--property=LoadState", "--value", name+".service").CombinedOutput()
		cancel()
		if strings.TrimSpace(string(b)) != "not-found" {
			t.Fatalf("refusing to replace existing %s unit: %s", name, b)
		}
	}
	unit := "/etc/systemd/system/alinksec-agent.service"
	contents := "[Unit]\nDescription=ALinkSec disposable upgrade validation\n[Service]\nType=simple\nUser=root\nExecStart=" + testUnitArg(binary) + " run --workdir " + testUnitArg(work) + "\nRestart=always\nRestartSec=1\nTimeoutStopSec=10\n"
	if err := os.WriteFile(unit, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Stop recovery first so it cannot race cleanup or resurrect the Agent.
		for _, name := range []string{"alinksec-agent-upgrade-watchdog", "alinksec-agent"} {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			exec.CommandContext(ctx, "systemctl", "stop", name+".service").Run()
			cancel()
		}
		watchUnit := "/etc/systemd/system/alinksec-agent-upgrade-watchdog.service"
		if b, err := os.ReadFile(watchUnit); err == nil {
			if strings.Contains(string(b), testUnitArg(work)) {
				exec.Command("systemctl", "disable", "alinksec-agent-upgrade-watchdog.service").Run()
				os.Remove(watchUnit)
			} else {
				t.Error("unrelated watchdog unit found during cleanup")
			}
		}
		os.Remove(unit)
		exec.Command("systemctl", "daemon-reload").Run()
		exec.Command("systemctl", "reset-failed").Run()
	})
	testSystemctl(t, "daemon-reload")
	return systemdUpgradeService{}
}
func (systemdUpgradeService) start(t *testing.T) { testSystemctl(t, "start", "alinksec-agent.service") }
func (systemdUpgradeService) stop(t *testing.T)  { testSystemctl(t, "stop", "alinksec-agent.service") }
func (systemdUpgradeService) pid(t *testing.T) int {
	value := testSystemctl(t, "show", "--property=MainPID", "--value", "alinksec-agent.service")
	pid, err := strconv.Atoi(value)
	if err != nil || pid <= 0 {
		t.Fatal(fmt.Sprintf("invalid Agent PID %s: %v", value, err))
	}
	return pid
}
func (systemdUpgradeService) restartWatchdog(t *testing.T) {
	testSystemctl(t, "restart", "alinksec-agent-upgrade-watchdog.service")
}
