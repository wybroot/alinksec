package baseline

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func rescueSpec() CheckSpec {
	return CheckSpec{Type: "systemd_rescue_policy", Target: "local-system", Operator: "eq", Expected: rescueReference, TimeoutMs: 1000}
}
func rescueJSON() string {
	raw, _ := json.Marshal(map[string]any{"type": "systemd_rescue_policy", "target": "local-system", "operator": "eq", "expected": rescueReference, "timeout_ms": 1000})
	return string(raw)
}
func rescueBusJSON(kind string, value any) ItemResult {
	raw, _ := json.Marshal(map[string]any{"type": kind, "data": value})
	return ItemResult{Actual: string(raw)}
}
func goodRescueSnapshot() rescueSnapshot {
	s := rescueSnapshot{Manager: map[string]string{"Version": "255.4-1ubuntu8.17", "SystemState": "running"}, Environment: []string{}, Cmdline: "BOOT_IMAGE=/boot/vmlinuz root=UUID=test ro console=ttyS0\n"}
	for i, target := range []string{"rescue.service", "emergency.service"} {
		s.Units[i] = rescueUnit{Properties: map[string]string{"Id": target, "LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead", "NeedDaemonReload": "no", "Type": "idle", "MainPID": "0", "PAMName": "", "RootDirectory": "", "RootImage": ""}, Command: maintenanceCommand{Path: "/usr/lib/systemd/systemd-sulogin-shell", Argv: []string{"/usr/lib/systemd/systemd-sulogin-shell", []string{"rescue", "emergency"}[i]}, Ignore: true}, Flags: []string{"ignore-failure"}, Environment: []string{"HOME=/root", "API_TOKEN=do-not-report-private-value"}}
	}
	return s
}
func rescueSnapshotQueries(s rescueSnapshot) rescueQueries {
	return rescueQueries{bus: maintenanceQueries{show: func(properties, target string) ItemResult {
		values := s.Manager
		if target != "" {
			index := 0
			if target == "emergency.service" {
				index = 1
			}
			values = s.Units[index].Properties
		}
		lines := []string{}
		for _, key := range strings.Split(properties, ",") {
			lines = append(lines, key+"="+values[key])
		}
		return ItemResult{Actual: strings.Join(lines, "\n")}
	}, property: func(target, iface, property string) ItemResult {
		if target == "" {
			return rescueBusJSON("as", s.Environment)
		}
		index := 0
		if target == "emergency.service" {
			index = 1
		}
		u := s.Units[index]
		switch property {
		case "ExecStartEx":
			return rescueBusJSON("a(sasasttttuii)", []any{[]any{u.Command.Path, u.Command.Argv, u.Flags, 0, 0, 0, 0, 0, 0, 0}})
		case "Environment":
			return rescueBusJSON("as", u.Environment)
		case "EnvironmentFiles":
			return rescueBusJSON("a(sb)", []any{})
		default:
			return rescueBusJSON("as", []string{})
		}
	}}, cmdline: func() (string, error) { return s.Cmdline, nil }}
}
func TestRescueDefinitionBoundary(t *testing.T) {
	var doc map[string]any
	json.Unmarshal([]byte(rescueJSON()), &doc)
	if _, err := ParseCheck(rescueJSON()); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]any{"target": "other.service", "operator": "contains", "expected": "sulogin", "timeout_ms": 0, "option": nil, "cmd": nil, "connection": nil, "units": nil, "environment": nil} {
		copy := map[string]any{}
		for k, v := range doc {
			copy[k] = v
		}
		copy[key] = value
		raw, _ := json.Marshal(copy)
		if _, err := ParseCheck(string(raw)); err == nil {
			t.Fatal(key)
		}
	}
	doc["timeout_ms"] = nil
	raw, _ := json.Marshal(doc)
	if _, err := ParseCheck(string(raw)); err == nil {
		t.Fatal("null timeout")
	}
	delete(doc, "timeout_ms")
	raw, _ = json.Marshal(doc)
	if s, err := ParseCheck(string(raw)); err != nil || s.TimeoutMs != 5000 {
		t.Fatal(s, err)
	}
	if runtime.GOOS == "windows" {
		s := rescueSpec()
		if r := checkSystemdRescue(&s); !r.Error || r.Passed {
			t.Fatal(r)
		}
	}
}
func TestRescueLaunchStatesAndRedaction(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		change               func(*rescueSnapshot)
		pass, executionError bool
	}{
		{"both_loaded", func(s *rescueSnapshot) {}, true, false},
		{"unit_force", func(s *rescueSnapshot) {
			s.Units[1].Environment = append(s.Units[1].Environment, rescueForceVariable+"=yes")
		}, false, false},
		{"manager_force", func(s *rescueSnapshot) { s.Environment = []string{rescueForceVariable + "=1"} }, false, false},
		{"kernel_force", func(s *rescueSnapshot) { s.Cmdline += " " + rescueForceVariable }, false, false},
		{"explicit_false", func(s *rescueSnapshot) {
			s.Units[0].Environment = append(s.Units[0].Environment, rescueForceVariable+"=off")
			s.Environment = []string{rescueForceVariable + "=NO"}
			s.Cmdline += " " + rescueForceVariable + "=0"
		}, true, false},
		{"other_command", func(s *rescueSnapshot) { s.Units[0].Command.Path = "/bin/sh" }, false, false},
		{"argv_spoof", func(s *rescueSnapshot) { s.Units[0].Command.Argv = []string{"systemd-sulogin-shell rescue"} }, false, false},
		{"mode_mismatch", func(s *rescueSnapshot) { s.Units[1].Command.Argv[1] = "rescue" }, false, false},
		{"extra_arg", func(s *rescueSnapshot) { s.Units[0].Command.Argv = append(s.Units[0].Command.Argv, "--force") }, false, false},
		{"privileged_prefix", func(s *rescueSnapshot) { s.Units[0].Flags = []string{"privileged"} }, false, false},
		{"no_ignore_prefix", func(s *rescueSnapshot) { s.Units[0].Flags = []string{} }, true, false},
		{"wrong_type", func(s *rescueSnapshot) { s.Units[0].Properties["Type"] = "simple" }, false, false},
		{"masked", func(s *rescueSnapshot) { s.Units[0].Properties["LoadState"] = "masked" }, false, false},
		{"missing", func(s *rescueSnapshot) { s.Units[1].Properties["LoadState"] = "not-found" }, false, true},
		{"alias", func(s *rescueSnapshot) { s.Units[0].Properties["Id"] = "other.service" }, false, true},
		{"pending_reload", func(s *rescueSnapshot) { s.Units[1].Properties["NeedDaemonReload"] = "yes" }, false, true},
		{"transition", func(s *rescueSnapshot) { s.Units[0].Properties["ActiveState"] = "activating" }, false, true},
		{"bad_pid", func(s *rescueSnapshot) { s.Units[0].Properties["MainPID"] = "-1" }, false, true},
		{"unknown_type", func(s *rescueSnapshot) { s.Units[0].Properties["Type"] = "unknown" }, false, true},
		{"other_version", func(s *rescueSnapshot) { s.Manager["Version"] = "256" }, false, true},
		{"pam_chain", func(s *rescueSnapshot) { s.Units[0].Properties["PAMName"] = "login" }, false, true},
		{"alternate_root", func(s *rescueSnapshot) { s.Units[0].Properties["RootDirectory"] = "/private" }, false, true},
		{"force_unknown", func(s *rescueSnapshot) {
			s.Units[0].Environment = []string{rescueForceVariable + "=do-not-report-private-value"}
		}, false, true},
		{"duplicate_environment", func(s *rescueSnapshot) {
			s.Environment = []string{rescueForceVariable + "=no", rescueForceVariable + "=yes"}
		}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := goodRescueSnapshot()
			tc.change(&s)
			r := evaluateRescue([2]string{"rescue.service", "emergency.service"}, s)
			if r.Passed != tc.pass || r.Error != tc.executionError {
				t.Fatal(r)
			}
			if strings.Contains(r.Actual+r.Message, "do-not-report") || !strings.Contains(r.Actual, "authentication_state=unverified") {
				t.Fatal(r)
			}
		})
	}
}
func TestRescueTypedBusAndForceBoundaries(t *testing.T) {
	for _, tc := range []struct {
		raw, want string
		bad       bool
	}{
		{"ro quiet", "absent", false},
		{"SYSTEMD_SULOGIN_FORCE", "true", false},
		{"SYSTEMD-SULOGIN-FORCE=YES", "true", false},
		{"SYSTEMD_SULOGIN_FORCE=False", "false", false},
		{"other=SYSTEMD_SULOGIN_FORCE=1", "absent", false},
		{"SYSTEMD_SULOGIN_FORCE=", "", true},
		{"SYSTEMD_SULOGIN_FORCE=0 SYSTEMD_SULOGIN_FORCE=1", "", true},
		{"\"SYSTEMD_SULOGIN_FORCE=1\"", "", true},
		{"ro -- SYSTEMD_SULOGIN_FORCE=1", "", true},
		{"rd.SYSTEMD_SULOGIN_FORCE=1", "", true},
		{"ro\x00", "", true},
		{strings.Repeat("x", 16*1024+1), "", true},
	} {
		value, err := rescueCmdline(tc.raw)
		if (err != nil) != tc.bad || value != tc.want {
			t.Fatal(tc.raw, value, err)
		}
	}
	good := rescueSnapshotQueries(goodRescueSnapshot()).bus.property("rescue.service", "Service", "ExecStartEx")
	if c, f, err := rescueCommand(good); err != nil || len(f) != 1 || len(c.Argv) != 2 {
		t.Fatal(c, f, err)
	}
	for _, raw := range []string{`{"type":"as","data":null}`, `{"type":"as","data":[null]}`, `{"type":"as","data":[1]}`, `{"type":"as","data":["a"],"type":"as"}`, `{"type":"as","data":["a"]}{}`} {
		if _, err := rescueStrings(ItemResult{Actual: raw}); err == nil {
			t.Fatal(raw)
		}
	}
	for _, raw := range []string{strings.Replace(good.Actual, "ignore-failure", "unknown", 1), strings.Replace(good.Actual, `["ignore-failure"]`, `null`, 1), strings.Replace(good.Actual, `["ignore-failure"]`, `["ignore-failure","ignore-failure"]`, 1), strings.Replace(good.Actual, "a(sasasttttuii)", "a(sasbttttuii)", 1), good.Actual + "{}"} {
		if _, _, err := rescueCommand(ItemResult{Actual: raw}); err == nil {
			t.Fatal(raw)
		}
	}
	for _, property := range []string{"PassEnvironment", "UnsetEnvironment", "EnvironmentFiles", "Environment", "ExecStartEx"} {
		s := rescueSpec()
		q := rescueSnapshotQueries(goodRescueSnapshot())
		original := q.bus.property
		q.bus.property = func(a, b, c string) ItemResult {
			if c == property {
				if c == "EnvironmentFiles" {
					return rescueBusJSON("a(sb)", []any{[]any{"/do-not-report-private-value", true}})
				}
				return rescueBusJSON("as", []string{"do-not-report-private-value"})
			}
			return original(a, b, c)
		}
		r := observeRescue(context.Background(), &s, [2]string{"rescue.service", "emergency.service"}, q)
		if !r.Error || r.Passed || strings.Contains(r.Actual+r.Message, "do-not-report") {
			t.Fatal(property, r)
		}
	}
	if _, err := rescueStrings(rescueBusJSON("as", make([]string, 129))); err == nil {
		t.Fatal("array limit")
	}
	if _, err := rescueStrings(rescueBusJSON("as", []string{strings.Repeat("s", 4097)})); err == nil {
		t.Fatal("string limit")
	}
}
func TestRescueSharedDeadlineChangesAndFailures(t *testing.T) {
	for _, which := range []string{"deadline", "query_error", "environment_change", "command_change", "cmdline_change", "cmdline_error"} {
		s := rescueSpec()
		q := rescueSnapshotQueries(goodRescueSnapshot())
		ctx, cancel := context.WithCancel(context.Background())
		show := q.bus.show
		q.bus.show = func(a, b string) ItemResult {
			if which == "deadline" {
				cancel()
			}
			if which == "query_error" {
				return ItemResult{Error: true, Actual: "do-not-report-private-value"}
			}
			return show(a, b)
		}
		property := q.bus.property
		n := 0
		q.bus.property = func(a, b, c string) ItemResult {
			r := property(a, b, c)
			if a == "" {
				n++
			}
			if n == 2 && which == "environment_change" && c == "Environment" {
				return rescueBusJSON("as", []string{"SECRET=do-not-report-private-value"})
			}
			if n == 2 && which == "command_change" && c == "ExecStartEx" {
				r.Actual = strings.ReplaceAll(r.Actual, "ignore-failure", "privileged")
			}
			return r
		}
		cmdline := q.cmdline
		reads := 0
		q.cmdline = func() (string, error) {
			reads++
			if which == "cmdline_error" {
				return "", fmt.Errorf("do-not-report-private-value")
			}
			raw, err := cmdline()
			if reads == 2 && which == "cmdline_change" {
				raw += " quiet"
			}
			return raw, err
		}
		r := observeRescue(ctx, &s, [2]string{"rescue.service", "emergency.service"}, q)
		cancel()
		if !r.Error || r.Passed || strings.Contains(r.Actual+r.Message, "do-not-report") {
			t.Fatal(which, r)
		}
	}
	s := rescueSpec()
	r := observeRescue(context.Background(), &s, [2]string{"rescue.service", "emergency.service"}, rescueSnapshotQueries(goodRescueSnapshot()))
	if !r.Passed || r.Error {
		t.Fatal(r)
	}
}
