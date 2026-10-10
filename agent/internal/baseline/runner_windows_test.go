//go:build windows

package baseline

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"time"
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

func TestFirewallQueryRejectsMissingProfilesInsteadOfPassingAnEmptyCount(t *testing.T) {
	var platforms map[string][]string
	if err := json.Unmarshal(commandRegistry, &platforms); err != nil {
		t.Fatal(err)
	}
	const prefix = "powershell.exe -NoProfile -NonInteractive -Command \""
	script := strings.TrimSuffix(strings.TrimPrefix(platforms["windows"][0], prefix), "\"")
	for _, test := range []struct {
		name, profiles string
		error, passed  bool
	}{
		{"none", "", true, false},
		{"two", "[pscustomobject]@{Enabled=$true}; [pscustomobject]@{Enabled=$true}", true, false},
		{"three enabled", "1..3 | ForEach-Object { [pscustomobject]@{Enabled=$true} }", false, true},
		{"one disabled", "[pscustomobject]@{Enabled=$false}; [pscustomobject]@{Enabled=$true}; [pscustomobject]@{Enabled=$true}", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			fixture := "function Get-NetFirewallProfile { param($PolicyStore,$ErrorAction); " + test.profiles + " }; "
			cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", fixture+script)
			result := executeBaselineCommand(ctx, cmd, &CheckSpec{Operator: "eq", Expected: "0", TimeoutMs: 30000})
			if result.Error != test.error || result.Passed != test.passed {
				t.Fatalf("firewall profile query: %+v", result)
			}
		})
	}
}
