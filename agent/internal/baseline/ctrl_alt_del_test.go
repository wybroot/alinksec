package baseline

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

const ctrlAltDelManagerFixture = "Version=255.4-1ubuntu8.11\nSystemState=running\nCtrlAltDelBurstAction=none"
const ctrlAltDelUnitFixture = "Id=ctrl-alt-del.target\nNames=ctrl-alt-del.target\nLoadState=masked\nActiveState=inactive\nSubState=dead\nUnitFileState=masked\nNeedDaemonReload=no"

func TestCtrlAltDelDefinitionBoundary(t *testing.T) {
	valid := `{"type":"systemd_ctrl_alt_del","target":"ctrl-alt-del.target","operator":"eq","expected":"masked/inactive/dead,burst_action=none"}`
	cs, err := ParseCheck(valid)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" && !checkCtrlAltDel(cs).Error {
		t.Fatal("Linux query accepted on Windows")
	}
	for _, invalid := range []string{
		strings.Replace(valid, "ctrl-alt-del.target", "reboot.target", 1),
		strings.Replace(valid, "ctrl-alt-del.target", "--user", 1),
		strings.Replace(valid, ctrlAltDelReference, "masked", 1),
		strings.Replace(valid, `"eq"`, `"regex"`, 1),
		strings.Replace(valid, `"type":`, `"cmd":null,"type":`, 1),
		strings.Replace(valid, `"type":`, `"connection":null,"type":`, 1),
		strings.Replace(valid, `"type":`, `"option":"--host=remote","type":`, 1),
	} {
		if _, err := ParseCheck(invalid); err == nil {
			t.Fatalf("unsafe definition accepted: %s", invalid)
		}
	}
}

func TestCtrlAltDelSnapshotClassification(t *testing.T) {
	for _, tc := range []struct {
		name, manager, unit    string
		passed, executionError bool
	}{
		{"masked with burst disabled", ctrlAltDelManagerFixture, ctrlAltDelUnitFixture, true, false},
		{"runtime mask", ctrlAltDelManagerFixture, strings.Replace(ctrlAltDelUnitFixture, "UnitFileState=masked", "UnitFileState=masked-runtime", 1), true, false},
		{"mask does not disable burst reboot", strings.Replace(ctrlAltDelManagerFixture, "=none", "=reboot-force", 1), ctrlAltDelUnitFixture, false, false},
		{"burst poweroff", strings.Replace(ctrlAltDelManagerFixture, "=none", "=poweroff-immediate", 1), ctrlAltDelUnitFixture, false, false},
		{"disabled does not mean masked", ctrlAltDelManagerFixture, strings.Replace(strings.Replace(ctrlAltDelUnitFixture, "LoadState=masked", "LoadState=loaded", 1), "UnitFileState=masked", "UnitFileState=disabled", 1), false, false},
		{"loaded alias to reboot", ctrlAltDelManagerFixture, "Id=reboot.target\nNames=reboot.target ctrl-alt-del.target\nLoadState=loaded\nActiveState=inactive\nSubState=dead\nUnitFileState=static\nNeedDaemonReload=no", false, false},
		{"active mask", ctrlAltDelManagerFixture, strings.Replace(strings.Replace(ctrlAltDelUnitFixture, "ActiveState=inactive", "ActiveState=active", 1), "SubState=dead", "SubState=active", 1), false, false},
		{"wrong identity", ctrlAltDelManagerFixture, strings.Replace(ctrlAltDelUnitFixture, "Names=ctrl-alt-del.target", "Names=reboot.target", 1), false, true},
		{"duplicate names", ctrlAltDelManagerFixture, strings.Replace(ctrlAltDelUnitFixture, "Names=ctrl-alt-del.target", "Names=ctrl-alt-del.target ctrl-alt-del.target", 1), false, true},
		{"missing target", ctrlAltDelManagerFixture, strings.Replace(ctrlAltDelUnitFixture, "LoadState=masked", "LoadState=not-found", 1), false, true},
		{"pending reload", ctrlAltDelManagerFixture, strings.Replace(ctrlAltDelUnitFixture, "NeedDaemonReload=no", "NeedDaemonReload=yes", 1), false, true},
		{"invalid reload boolean", ctrlAltDelManagerFixture, strings.Replace(ctrlAltDelUnitFixture, "NeedDaemonReload=no", "NeedDaemonReload=false", 1), false, true},
		{"target transition", ctrlAltDelManagerFixture, strings.Replace(ctrlAltDelUnitFixture, "ActiveState=inactive", "ActiveState=activating", 1), false, true},
		{"manager transition", strings.Replace(ctrlAltDelManagerFixture, "=running", "=stopping", 1), ctrlAltDelUnitFixture, false, true},
		{"future manager", strings.Replace(ctrlAltDelManagerFixture, "255.4", "256.4", 1), ctrlAltDelUnitFixture, false, true},
		{"unknown burst", strings.Replace(ctrlAltDelManagerFixture, "=none", "=future-action", 1), ctrlAltDelUnitFixture, false, true},
		{"duplicate property", ctrlAltDelManagerFixture + "\nCtrlAltDelBurstAction=none", ctrlAltDelUnitFixture, false, true},
		{"partial query", ctrlAltDelManagerFixture, strings.Replace(ctrlAltDelUnitFixture, "\nNeedDaemonReload=no", "", 1), false, true},
		{"extra property", ctrlAltDelManagerFixture, ctrlAltDelUnitFixture + "\nOther=no", false, true},
		{"diagnostic contamination", ctrlAltDelManagerFixture + "\nWarning: disconnected", ctrlAltDelUnitFixture, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := evaluateCtrlAltDel(ItemResult{Actual: tc.manager}, ItemResult{Actual: tc.unit}, "ctrl-alt-del.target")
			if result.Passed != tc.passed || result.Error != tc.executionError || !strings.Contains(result.Actual, "trigger_test_state=unverified") {
				t.Fatalf("classification: %+v", result)
			}
		})
	}
}

func TestCtrlAltDelSharedDeadlineAndObservedChange(t *testing.T) {
	for _, mode := range []string{"stable", "changed-manager", "changed-target", "deadline", "query-error"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			result := observeCtrlAltDel(ctx, 1000, "ctrl-alt-del.target", func(properties, target string) ItemResult {
				calls++
				if mode == "deadline" && calls == 1 {
					cancel()
				}
				if mode == "query-error" {
					return ItemResult{Error: true, Actual: ctrlAltDelManagerFixture, Message: "query exited 7"}
				}
				if target == "" {
					value := ctrlAltDelManagerFixture
					if mode == "changed-manager" && calls == 3 {
						value = strings.Replace(value, "=none", "=reboot-force", 1)
					}
					return ItemResult{Actual: value}
				}
				value := ctrlAltDelUnitFixture
				if mode == "changed-target" && calls == 4 {
					value = strings.Replace(value, "UnitFileState=masked", "UnitFileState=masked-runtime", 1)
				}
				return ItemResult{Actual: value}
			})
			if result.Passed != (mode == "stable") || result.Error != (mode != "stable") {
				t.Fatalf("observed change/deadline: %+v", result)
			}
			if mode == "deadline" && calls != 1 || mode == "query-error" && calls != 1 || mode == "stable" && calls != 4 {
				t.Fatalf("unexpected query count %d", calls)
			}
		})
	}
}

func TestCtrlAltDelCommandFailureCannotBecomeMasked(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux command failure fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "printf 'Version=255\\nSystemState=running\\nCtrlAltDelBurstAction=none\\n'; exit 7")
	result := evaluateCtrlAltDel(collectBaselineCommand(ctx, cmd, 1000), ItemResult{Actual: ctrlAltDelUnitFixture}, "ctrl-alt-del.target")
	if !result.Error || result.Passed || !strings.Contains(result.Actual, "CtrlAltDelBurstAction=none") {
		t.Fatalf("exit failure lost: %+v", result)
	}
}
