package baseline

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func maintenanceSpec(option string) CheckSpec {
	return CheckSpec{Type: "systemd_maintenance", Target: "local-system", Option: option, Operator: "eq", Expected: maintenanceReferences[option], TimeoutMs: 1000}
}
func maintenanceJSON(s CheckSpec) string {
	raw, _ := json.Marshal(map[string]any{"type": s.Type, "target": s.Target, "option": s.Option, "operator": s.Operator, "expected": s.Expected, "timeout_ms": s.TimeoutMs})
	return string(raw)
}
func maintenanceExecJSON(path string, argv []string) string {
	raw, _ := json.Marshal(map[string]any{"type": "a(sasbttttuii)", "data": []any{[]any{path, argv, false, 0, 0, 0, 0, 0, 0, 0}}})
	return string(raw)
}
func goodMaintenanceSnapshot(option string) maintenanceSnapshot {
	t := systemMaintenanceTargets()
	target := t.sync
	kind := "notify"
	active, sub, pid := "active", "running", "42"
	if option == "tmpfiles_clean" {
		target = t.cleaner
		kind = "oneshot"
		active, sub, pid = "inactive", "dead", "0"
	}
	s := maintenanceSnapshot{Manager: map[string]string{"Version": "255.4-1ubuntu8.17", "SystemState": "running"}, Service: map[string]string{"Id": target, "LoadState": "loaded", "ActiveState": active, "SubState": sub, "NeedDaemonReload": "no", "Type": kind, "RemainAfterExit": "no", "MainPID": pid}, Clock: kernelClockSample{0, 0x2001, 100, 100}, Next: 100000000}
	if option == "tmpfiles_clean" {
		s.Timer = map[string]string{"Id": t.timer, "LoadState": "loaded", "ActiveState": "active", "SubState": "waiting", "NeedDaemonReload": "no", "Unit": t.cleaner}
		s.Command = maintenanceCommand{Path: "/usr/bin/systemd-tmpfiles", Argv: []string{"systemd-tmpfiles", "--clean"}}
	} else {
		s.Command = maintenanceCommand{Path: "/usr/lib/systemd/systemd-timesyncd", Argv: []string{"/usr/lib/systemd/systemd-timesyncd"}}
	}
	return s
}
func TestMaintenanceDefinitionBoundary(t *testing.T) {
	for option := range maintenanceReferences {
		s := maintenanceSpec(option)
		if _, err := ParseCheck(maintenanceJSON(s)); err != nil {
			t.Fatal(err)
		}
		for _, change := range []func(*CheckSpec){func(s *CheckSpec) { s.Target = "other.service" }, func(s *CheckSpec) { s.Option = "clock_set" }, func(s *CheckSpec) { s.Expected = "active" }, func(s *CheckSpec) { s.Operator = "contains" }, func(s *CheckSpec) { s.TimeoutMs = 0 }} {
			bad := s
			change(&bad)
			if _, err := ParseCheck(maintenanceJSON(bad)); err == nil {
				t.Fatal("weak maintenance accepted")
			}
		}
		var doc map[string]any
		json.Unmarshal([]byte(maintenanceJSON(s)), &doc)
		for _, field := range []string{"cmd", "bus", "connection", "owner", "uid_min", "units"} {
			doc[field] = nil
			raw, _ := json.Marshal(doc)
			if _, err := ParseCheck(string(raw)); err == nil {
				t.Fatal(field)
			}
			delete(doc, field)
		}
		doc["timeout_ms"] = nil
		raw, _ := json.Marshal(doc)
		if _, err := ParseCheck(string(raw)); err == nil {
			t.Fatal("null timeout")
		}
		if runtime.GOOS == "windows" {
			if r := checkSystemdMaintenance(&s); !r.Error || r.Passed {
				t.Fatal(r)
			}
		}
	}
}
func TestMaintenanceSeparatesStatesFromDelivery(t *testing.T) {
	for _, tc := range []struct {
		name, option         string
		change               func(*maintenanceSnapshot)
		pass, executionError bool
	}{
		{"waiting", "tmpfiles_clean", func(s *maintenanceSnapshot) {}, true, false},
		{"inactive_timer", "tmpfiles_clean", func(s *maintenanceSnapshot) { s.Timer["ActiveState"] = "inactive"; s.Timer["SubState"] = "dead" }, false, false},
		{"wrong_target", "tmpfiles_clean", func(s *maintenanceSnapshot) { s.Timer["Unit"] = "other.service" }, false, false},
		{"remain_after_exit", "tmpfiles_clean", func(s *maintenanceSnapshot) { s.Service["RemainAfterExit"] = "yes" }, false, false},
		{"zero_next", "tmpfiles_clean", func(s *maintenanceSnapshot) { s.Next = 0 }, false, false},
		{"infinity_next", "tmpfiles_clean", func(s *maintenanceSnapshot) { s.Next = ^uint64(0) }, false, false},
		{"flattened_argv_spoof", "tmpfiles_clean", func(s *maintenanceSnapshot) { s.Command.Argv = []string{"systemd-tmpfiles --clean"} }, false, false},
		{"wrong_command", "tmpfiles_clean", func(s *maintenanceSnapshot) { s.Command.Path = "/usr/bin/true" }, false, false},
		{"ignore_errors", "tmpfiles_clean", func(s *maintenanceSnapshot) { s.Command.Ignore = true }, false, false},
		{"pending_reload", "tmpfiles_clean", func(s *maintenanceSnapshot) { s.Timer["NeedDaemonReload"] = "yes" }, false, true},
		{"timer_transition", "tmpfiles_clean", func(s *maintenanceSnapshot) { s.Timer["SubState"] = "running" }, false, true},
		{"sync", "time_sync", func(s *maintenanceSnapshot) {}, true, false},
		{"running_unsynced", "time_sync", func(s *maintenanceSnapshot) { s.Clock.State = 5; s.Clock.Status = 0x40 }, false, false},
		{"hardware_clock_error", "time_sync", func(s *maintenanceSnapshot) { s.Clock.State = 5; s.Clock.Status = 0x1000 }, false, false},
		{"pps_error", "time_sync", func(s *maintenanceSnapshot) { s.Clock.State = 5; s.Clock.Status = 0x2 }, false, false},
		{"leap_pending", "time_sync", func(s *maintenanceSnapshot) { s.Clock.State = 1; s.Clock.Status = 0x2011 }, true, false},
		{"sync_but_service_stopped", "time_sync", func(s *maintenanceSnapshot) {
			s.Service["ActiveState"] = "inactive"
			s.Service["SubState"] = "dead"
			s.Service["MainPID"] = "0"
		}, false, false},
		{"wrong_program_name", "time_sync", func(s *maintenanceSnapshot) { s.Command.Path = "/usr/bin/sleep" }, false, false},
		{"unknown_clock", "time_sync", func(s *maintenanceSnapshot) { s.Clock.State = 6 }, false, true},
		{"unknown_status", "time_sync", func(s *maintenanceSnapshot) { s.Clock.Status = 0x10000 }, false, true},
		{"manager_version", "time_sync", func(s *maintenanceSnapshot) { s.Manager["Version"] = "254" }, false, true},
		{"missing_service", "time_sync", func(s *maintenanceSnapshot) { s.Service["LoadState"] = "not-found" }, false, true},
		{"unknown_type", "time_sync", func(s *maintenanceSnapshot) { s.Service["Type"] = "arbitrary" }, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := goodMaintenanceSnapshot(tc.option)
			tc.change(&s)
			r := evaluateMaintenance(tc.option, systemMaintenanceTargets(), s)
			if r.Passed != tc.pass || r.Error != tc.executionError {
				t.Fatal(r)
			}
			if !strings.Contains(r.Actual, "snapshot_state=non_atomic") {
				t.Fatal(r)
			}
		})
	}
}
func TestMaintenanceTypedBusPreservesArgumentsAndRejectsMalformedData(t *testing.T) {
	good := maintenanceExecJSON("/usr/bin/systemd-tmpfiles", []string{"systemd-tmpfiles", "--clean"})
	if c, err := parseMaintenanceCommand(ItemResult{Actual: good}); err != nil || !c.matches("tmpfiles_clean") {
		t.Fatal(c, err)
	}
	spoof := maintenanceExecJSON("/usr/bin/systemd-tmpfiles", []string{"systemd-tmpfiles --clean"})
	if c, err := parseMaintenanceCommand(ItemResult{Actual: spoof}); err != nil || c.matches("tmpfiles_clean") {
		t.Fatal(c, err)
	}
	for _, raw := range []string{`{"type":"t","data":1}`, `{"type":"a(sasbttttuii)","data":null}`, `{"type":"a(sasbttttuii)","type":"a(sasbttttuii)","data":[]}`, `{"type":"a(sasbttttuii)","data":[[null,[],false,0,0,0,0,0,0,0]]}`, `{"type":"a(sasbttttuii)","data":[["/usr/bin/systemd-tmpfiles",null,false,0,0,0,0,0,0,0]]}`, strings.Replace(good, ",false,", ",null,", 1), strings.Replace(good, ",false,0", ",false,18446744073709551616", 1), good + "{}"} {
		if _, err := parseMaintenanceCommand(ItemResult{Actual: raw}); err == nil {
			t.Fatal("malformed bus data", raw)
		}
	}
	for _, raw := range []string{`"1"`, `1.0`, `-1`, `18446744073709551616`, `null`} {
		if _, err := maintenanceUint(json.RawMessage(raw), 64); err == nil {
			t.Fatal(raw)
		}
	}
}
func snapshotMaintenanceQueries(s maintenanceSnapshot) maintenanceQueries {
	text := func(values map[string]string) ItemResult {
		var lines []string
		for k, v := range values {
			lines = append(lines, k+"="+v)
		}
		return ItemResult{Actual: strings.Join(lines, "\n")}
	}
	return maintenanceQueries{show: func(props, target string) ItemResult {
		if target == "" {
			return text(s.Manager)
		}
		if strings.HasSuffix(target, ".timer") {
			return text(s.Timer)
		}
		return text(s.Service)
	}, property: func(target, iface, property string) ItemResult {
		if property == "NextElapseUSecMonotonic" {
			return ItemResult{Actual: fmt.Sprintf(`{"type":"t","data":%d}`, s.Next)}
		}
		return ItemResult{Actual: maintenanceExecJSON(s.Command.Path, s.Command.Argv)}
	}, clock: func() (kernelClockSample, error) { return s.Clock, nil }}
}
func TestMaintenanceSharedDeadlineAndChanges(t *testing.T) {
	cs := maintenanceSpec("time_sync")
	s := goodMaintenanceSnapshot(cs.Option)
	for _, which := range []string{"state", "command", "deadline", "clock_error", "query_error"} {
		q := snapshotMaintenanceQueries(s)
		original := q.show
		calls := 0
		ctx, cancel := context.WithCancel(context.Background())
		q.show = func(properties, target string) ItemResult {
			calls++
			if which == "query_error" {
				return ItemResult{Error: true, Actual: "must_not_echo_credentials"}
			}
			if which == "deadline" {
				cancel()
			}
			r := original(properties, target)
			if which == "state" && calls > 2 {
				r.Actual = strings.ReplaceAll(r.Actual, "MainPID=42", "MainPID=43")
			}
			return r
		}
		if which == "command" {
			original := q.property
			n := 0
			q.property = func(a, b, c string) ItemResult {
				n++
				r := original(a, b, c)
				if n == 2 {
					r.Actual = strings.ReplaceAll(r.Actual, "/usr/lib/systemd/systemd-timesyncd", "/usr/bin/sleep")
				}
				return r
			}
		}
		if which == "clock_error" {
			q.clock = func() (kernelClockSample, error) { return kernelClockSample{}, fmt.Errorf("not available") }
		}
		r := observeMaintenance(ctx, &cs, systemMaintenanceTargets(), q)
		cancel()
		if !r.Error || r.Passed || strings.Contains(r.Actual, "must_not_echo_credentials") {
			t.Fatal(which, r)
		}
	}
}
