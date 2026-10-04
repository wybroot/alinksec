//go:build windows

package baseline

import (
	"encoding/json"
	"testing"
)

func TestNativeWindowsBaselineReadsEventLogService(t *testing.T) {
	var platforms map[string][]string
	if err := json.Unmarshal(commandRegistry, &platforms); err != nil {
		t.Fatal(err)
	}
	result := checkCmdOutput(&CheckSpec{Type: "cmd_output", Cmd: platforms["windows"][2], Operator: "eq", Expected: "Running", TimeoutMs: 15000})
	if !result.Passed {
		t.Fatalf("native Windows service query: %+v", result)
	}
	if isApprovedCmdOutput("sysctl -n net.ipv4.ip_forward") {
		t.Fatal("Linux selector must be rejected on Windows")
	}
	if isApprovedCmdOutput(platforms["windows"][2] + " & echo injected") {
		t.Fatal("modified PowerShell selector must be rejected")
	}
}
