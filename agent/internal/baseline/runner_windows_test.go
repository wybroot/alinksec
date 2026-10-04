//go:build windows

package baseline

import (
	"encoding/json"
	"testing"
)

func TestNativeWindowsBaselineQueriesReturnEvidence(t *testing.T) {
	var platforms map[string][]string
	if err := json.Unmarshal(commandRegistry, &platforms); err != nil {
		t.Fatal(err)
	}
	queries := []struct{ name, output string }{
		{"firewall profiles", "^[0-3]$"},
		{"Defender real-time protection", "^(True|False)$"},
		{"Event Log service", "^Running$"},
		{"UAC", "^[01]$"},
	}
	for index, query := range queries {
		t.Run(query.name, func(t *testing.T) {
			result := checkCmdOutput(&CheckSpec{Type: "cmd_output", Cmd: platforms["windows"][index], Operator: "regex", Expected: query.output, TimeoutMs: 30000})
			if !result.Passed {
				t.Fatalf("native Windows query: %+v", result)
			}
			t.Logf("native observation: %s", result.Actual)
		})
	}
	if isApprovedCmdOutput("sysctl -n net.ipv4.ip_forward") {
		t.Fatal("Linux selector must be rejected on Windows")
	}
	if isApprovedCmdOutput(platforms["windows"][2] + " & echo injected") {
		t.Fatal("modified PowerShell selector must be rejected")
	}
}
