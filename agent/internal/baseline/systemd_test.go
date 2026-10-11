package baseline

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSystemdDefinitionBoundary(t *testing.T) {
	valid := `{"type":"systemd_service","target":"auditd.service","operator":"eq","expected":"loaded/active/running"}`
	for _, definition := range []string{valid, strings.Replace(valid, "auditd", "rsyslog", 1)} {
		cs, err := ParseCheck(definition)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS == "windows" && !checkSystemdService(cs).Error {
			t.Fatal("Linux check accepted on Windows")
		}
	}
	for _, invalid := range []string{
		strings.Replace(valid, "auditd.service", "sshd.service", 1),
		strings.Replace(valid, "auditd.service", "--user", 1),
		strings.Replace(valid, "auditd.service", "auditd.service;touch /tmp/injected", 1),
		strings.Replace(valid, "loaded/active/running", "active", 1),
		strings.Replace(valid, `"eq"`, `"regex"`, 1),
		strings.Replace(valid, `"type":`, `"cmd":null,"type":`, 1),
		strings.Replace(valid, `"type":`, `"connection":null,"type":`, 1),
		strings.Replace(valid, `"type":`, `"option":"running","type":`, 1),
		strings.Replace(valid, `"type":`, `"uid_min":null,"type":`, 1),
	} {
		if _, err := ParseCheck(invalid); err == nil {
			t.Fatalf("unsafe definition accepted: %s", invalid)
		}
	}
}

func TestSystemdSnapshotClassification(t *testing.T) {
	output := "Id=auditd.service\nLoadState=loaded\nActiveState=active\nSubState=running\nMainPID=42"
	for _, tc := range []struct {
		name, from, to         string
		passed, executionError bool
	}{
		{"running", "", "", true, false},
		{"inactive", "ActiveState=active\nSubState=running\nMainPID=42", "ActiveState=inactive\nSubState=dead\nMainPID=0", false, false},
		{"failed", "ActiveState=active\nSubState=running\nMainPID=42", "ActiveState=failed\nSubState=failed\nMainPID=0", false, false},
		{"oneshot is not daemon", "SubState=running\nMainPID=42", "SubState=exited\nMainPID=0", false, false},
		{"masked while still running", "LoadState=loaded", "LoadState=masked", false, false},
		{"missing unit", "LoadState=loaded", "LoadState=not-found", false, true},
		{"bad unit", "LoadState=loaded", "LoadState=bad-setting", false, true},
		{"transition", "ActiveState=active\nSubState=running", "ActiveState=activating\nSubState=start", false, true},
		{"future state", "ActiveState=active", "ActiveState=future", false, true},
		{"inconsistent snapshot", "SubState=running", "SubState=dead", false, true},
		{"missing pid", "MainPID=42", "MainPID=0", false, true},
		{"pid overflow", "MainPID=42", "MainPID=4294967296", false, true},
		{"alias", "Id=auditd.service", "Id=other.service", false, true},
		{"partial", "MainPID=42", "", false, true},
		{"duplicate", "MainPID=42", "MainPID=42\nMainPID=0", false, true},
		{"diagnostic contamination", "MainPID=42", "MainPID=42\nWarning: disconnected", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := output
			if tc.from != "" {
				value = strings.Replace(value, tc.from, tc.to, 1)
			}
			result := evaluateSystemdService(ItemResult{Actual: value}, "auditd.service")
			if result.Passed != tc.passed || result.Error != tc.executionError {
				t.Fatalf("classification: %+v", result)
			}
			if !strings.Contains(result.Actual, "unit=auditd.service") {
				t.Fatal("unit evidence lost")
			}
		})
	}
}

func TestSystemdCommandFailureCannotBecomeRunning(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux execution fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "printf 'Id=auditd.service\\nLoadState=loaded\\nActiveState=active\\nSubState=running\\nMainPID=42\\n'; exit 7")
	result := evaluateSystemdService(collectBaselineCommand(ctx, cmd, 1000), "auditd.service")
	if !result.Error || result.Passed || !strings.Contains(result.Actual, "ActiveState=active") {
		t.Fatalf("exit failure lost: %+v", result)
	}
}
