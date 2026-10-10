package baseline

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func ipv4HostSpec(option string) CheckSpec {
	return CheckSpec{Type: "linux_ipv4_host", Target: ipv4HostTarget, Option: option, Operator: "eq", Expected: ipv4HostReferences[option], TimeoutMs: 1000}
}
func ipv4HostJSON(s CheckSpec) string {
	b, _ := json.Marshal(map[string]any{"type": s.Type, "target": s.Target, "option": s.Option, "operator": s.Operator, "expected": s.Expected, "timeout_ms": s.TimeoutMs})
	return string(b)
}
func TestIPv4HostDefinitionBoundary(t *testing.T) {
	for option := range ipv4HostReferences {
		s := ipv4HostSpec(option)
		if _, err := ParseCheck(ipv4HostJSON(s)); err != nil {
			t.Fatal(err)
		}
		for _, mutate := range []func(*CheckSpec){func(s *CheckSpec) { s.Target = "/etc/sysctl.conf" }, func(s *CheckSpec) { s.Option = "arbitrary" }, func(s *CheckSpec) { s.Expected = "0" }, func(s *CheckSpec) { s.Operator = "regex" }, func(s *CheckSpec) { s.TimeoutMs = 0 }} {
			bad := s
			mutate(&bad)
			if _, err := ParseCheck(ipv4HostJSON(bad)); err == nil {
				t.Fatal("weak definition accepted")
			}
		}
		var doc map[string]any
		json.Unmarshal([]byte(ipv4HostJSON(s)), &doc)
		for _, field := range []string{"cmd", "regex", "connection", "owner", "uid_min", "role_path", "interfaces"} {
			doc[field] = nil
			b, _ := json.Marshal(doc)
			if _, err := ParseCheck(string(b)); err == nil {
				t.Fatal("extension accepted", field)
			}
			delete(doc, field)
		}
		doc["timeout_ms"] = nil
		b, _ := json.Marshal(doc)
		if _, err := ParseCheck(string(b)); err == nil {
			t.Fatal("null timeout accepted")
		}
		delete(doc, "timeout_ms")
		b, _ = json.Marshal(doc)
		if parsed, err := ParseCheck(string(b)); err != nil || parsed.TimeoutMs != 5000 {
			t.Fatal("omitted timeout", err)
		}
	}
	if runtime.GOOS == "windows" {
		s := ipv4HostSpec("rp_filter")
		if r := checkIPv4Host(&s); !r.Error || r.Passed {
			t.Fatal(r)
		}
	}
}

func goodIPv4Snapshot() ipv4HostSnapshot {
	return ipv4HostSnapshot{Namespace: "4:123", Interfaces: map[string]ipv4HostValues{"all": {1, 0}, "default": {0, 0}, "lo": {0, 0}, "enp0s1.42": {1, 0}}}
}
func TestIPv4HostKernelSemantics(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		mutate                      func(*ipv4HostSnapshot)
		rp, forward, executionError bool
	}{
		{"all_provides_strict", func(s *ipv4HostSnapshot) {}, true, true, false},
		{"interface_loose_overrides_all_strict", func(s *ipv4HostSnapshot) { s.Interfaces["enp0s1.42"] = ipv4HostValues{2, 0} }, false, true, false},
		{"all_loose_overrides_interface_strict", func(s *ipv4HostSnapshot) { s.Interfaces["all"] = ipv4HostValues{2, 0} }, false, true, false},
		{"each_strict_without_all", func(s *ipv4HostSnapshot) {
			for n := range s.Interfaces {
				s.Interfaces[n] = ipv4HostValues{1, 0}
			}
			s.Interfaces["all"] = ipv4HostValues{0, 0}
		}, true, true, false},
		{"disabled_interface", func(s *ipv4HostSnapshot) { s.Interfaces["all"] = ipv4HostValues{0, 0} }, false, true, false},
		{"loose_future_default", func(s *ipv4HostSnapshot) { s.Interfaces["default"] = ipv4HostValues{2, 0} }, false, true, false},
		{"local_forwarding_with_global_zero", func(s *ipv4HostSnapshot) { s.Interfaces["lo"] = ipv4HostValues{0, 1} }, true, false, false},
		{"future_forwarding", func(s *ipv4HostSnapshot) { s.Interfaces["default"] = ipv4HostValues{0, 1} }, true, false, false},
		{"global_forwarding", func(s *ipv4HostSnapshot) { s.IPForward = 1; s.Interfaces["all"] = ipv4HostValues{1, 1} }, true, false, false},
		{"inconsistent_alias", func(s *ipv4HostSnapshot) { s.IPForward = 1 }, false, false, true},
		{"unknown_value", func(s *ipv4HostSnapshot) { s.Interfaces["lo"] = ipv4HostValues{3, 0} }, false, false, true},
		{"missing_default", func(s *ipv4HostSnapshot) { delete(s.Interfaces, "default") }, false, false, true},
		{"no_real_interfaces", func(s *ipv4HostSnapshot) { delete(s.Interfaces, "lo"); delete(s.Interfaces, "enp0s1.42") }, false, false, true},
		{"unsafe_name", func(s *ipv4HostSnapshot) { s.Interfaces["x/escape"] = ipv4HostValues{1, 0} }, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := goodIPv4Snapshot()
			tc.mutate(&s)
			for option, want := range map[string]bool{"rp_filter": tc.rp, "forwarding": tc.forward} {
				r := evaluateIPv4Host(option, s)
				if r.Error != tc.executionError || r.Passed != want {
					t.Fatal(option, r)
				}
				if !strings.Contains(r.Actual, "routing_state=unverified") {
					t.Fatal(r)
				}
			}
		})
	}
}
func TestIPv4HostChangesAndDeadlineAreErrors(t *testing.T) {
	cs := ipv4HostSpec("rp_filter")
	for _, mutate := range []func(*ipv4HostSnapshot){func(s *ipv4HostSnapshot) { s.Namespace = "different" }, func(s *ipv4HostSnapshot) { s.Interfaces["new0"] = ipv4HostValues{1, 0} }, func(s *ipv4HostSnapshot) { s.Interfaces["lo"] = ipv4HostValues{1, 0} }, func(s *ipv4HostSnapshot) { s.Identities = map[string]string{"path": "replaced"} }} {
		calls := 0
		r := observeIPv4Host(context.Background(), &cs, func() (ipv4HostSnapshot, error) {
			s := goodIPv4Snapshot()
			calls++
			if calls == 2 {
				mutate(&s)
			}
			return s, nil
		}, func() error { return nil })
		if !r.Error || r.Passed {
			t.Fatal(r)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := observeIPv4Host(ctx, &cs, func() (ipv4HostSnapshot, error) { cancel(); return goodIPv4Snapshot(), nil }, func() error { return nil })
	if !r.Error || r.Passed {
		t.Fatal(r)
	}
}
