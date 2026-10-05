//go:build linux

package baseline

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestRetiredFailureMaskingSelectorsAreRejected(t *testing.T) {
	selectors := []string{
		"stat -c %U /var/log/messages 2>/dev/null || echo root",
		"sysctl -n net.ipv6.conf.all.accept_redirects 2>/dev/null || echo 0",
		`sh -c "findmnt -n /tmp >/dev/null 2>&1 && findmnt -no OPTIONS /tmp | grep -cE 'nosuid|nodev' || echo 1"`,
		"systemctl is-active auditd 2>/dev/null || echo inactive",
		"find /usr/bin /usr/sbin /usr/local/bin -perm -4000 -newer /etc/passwd 2>/dev/null | wc -l",
	}
	for _, selector := range selectors {
		if isApprovedCmdOutput(selector) {
			t.Fatalf("retired selector still approved: %s", selector)
		}
		result := checkCmdOutput(&CheckSpec{Cmd: selector, Operator: "eq", Expected: "0", TimeoutMs: 1000})
		if !result.Error || result.Passed {
			t.Fatalf("retired selector did not return error: %+v", result)
		}
	}
}

func TestMessagesMetadataFollowsSymlinksAndRequiresARegularFile(t *testing.T) {
	root := t.TempDir()
	file, link := filepath.Join(root, "messages"), filepath.Join(root, "link")
	if err := os.WriteFile(file, []byte("log evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	query := func(path string) ItemResult {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		return executeBaselineCommand(ctx, exec.CommandContext(ctx, "stat", "-L", "-c", "%f %u", path),
			&CheckSpec{Operator: "regex", Expected: "^8[0-9a-f]{3} " + strconv.Itoa(os.Getuid()) + "$", TimeoutMs: 1000})
	}
	if result := query(link); result.Error || !result.Passed {
		t.Fatalf("link must report the regular target metadata: %+v", result)
	}
	if result := query(root); result.Error || result.Passed {
		t.Fatalf("a directory must not qualify as a log file: %+v", result)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if result := query(link); !result.Error || result.Passed {
		t.Fatalf("a dangling link must preserve stat failure: %+v", result)
	}
}

func TestReviewedQueriesPropagateFailureEvenWithPassingOutput(t *testing.T) {
	path := t.TempDir()
	for _, fixture := range []struct{ binary, output string }{{"stat", "81a4 0"}, {"sysctl", "0"}, {"findmnt", "rw,nosuid,nodev"}} {
		if err := os.WriteFile(filepath.Join(path, fixture.binary), []byte("#!/bin/sh\nprintf '%s\\n' '"+fixture.output+"'\nexit 1\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", path)
	for _, check := range []CheckSpec{
		{Cmd: "stat -L -c '%f %u' /var/log/messages", Operator: "regex", Expected: "^8[0-9a-f]{3} 0$"},
		{Cmd: "sysctl -n net.ipv6.conf.all.accept_redirects", Operator: "eq", Expected: "0"},
		{Cmd: "findmnt --noheadings --raw --output OPTIONS --target /tmp", Operator: "regex", Expected: ".*nosuid.*nodev.*"},
	} {
		check.TimeoutMs = 1000
		result := checkCmdOutput(&check)
		if result.Passed || !result.Error || result.Actual == "" {
			t.Fatalf("failed observation must retain evidence and return error: %+v", result)
		}
	}
}

func reviewedLinuxChecks(t *testing.T) []*CheckSpec {
	t.Helper()
	raw, err := os.ReadFile("../../../deploy/baseline/packages/reviewed/linux-baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Items []struct{ Check CheckSpec } `json:"items"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var checks []*CheckSpec
	for i := range doc.Items {
		checks = append(checks, &doc.Items[i].Check)
	}
	return checks
}

func TestTmpMountRequiresBothDistinctOptions(t *testing.T) {
	var mount *CheckSpec
	for _, check := range reviewedLinuxChecks(t) {
		if check.Cmd == "findmnt --noheadings --raw --output OPTIONS --target /tmp" {
			mount = check
		}
	}
	if mount == nil {
		t.Fatal("reviewed mount rule missing")
	}
	for _, test := range []struct {
		options string
		passed  bool
	}{
		{"rw,nosuid,nodev,relatime", true}, {"nodev,rw,nosuid", true}, {"nosuid,nodev", true},
		{"rw,nosuid", false}, {"rw,nodev", false}, {"rw", false}, {"", false},
		{"rw,xnosuid,nodev", false}, {"rw,nosuid,nodevice", false}, {"nosuid\nnodev", false}, {"nosuid,nodev\nrw,nodev,nosuid", true}, {"nosuid,nodev\nrw,nodev", false},
	} {
		result := evaluateOutput(test.options, mount)
		if result.Error || result.Passed != test.passed {
			t.Fatalf("mount options %q: %+v", test.options, result)
		}
	}
}

func TestNativeReviewedLinuxQueriesReturnEvidence(t *testing.T) {
	for _, check := range reviewedLinuxChecks(t) {
		t.Run(check.Cmd, func(t *testing.T) {
			copy := *check
			copy.Operator, copy.Expected = "regex", "^[^\\s]+(\\n[^\\s]+)*$"
			if check.Cmd == "stat -L -c '%f %u' /var/log/messages" {
				copy.Expected = "^[0-9a-f]+ [0-9]+$"
			}
			result := checkCmdOutput(&copy)
			// messages is not a universal Linux log path. Missing it must remain
			// a real observation error, never a synthetic root ownership pass.
			if check.Cmd == "stat -L -c '%f %u' /var/log/messages" {
				if _, err := os.Stat("/var/log/messages"); os.IsNotExist(err) {
					if !result.Error || result.Passed {
						t.Fatalf("missing messages must be an error: %+v", result)
					}
					t.Logf("native missing-file evidence: %s", result.Actual)
					return
				}
			}
			if result.Error || !result.Passed {
				t.Fatalf("native observation query failed: %+v", result)
			}
			t.Logf("native observation (not a compliance claim): %s", result.Actual)
		})
	}
}
