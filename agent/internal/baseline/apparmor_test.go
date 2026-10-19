package baseline

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func appArmorSpec() CheckSpec {
	return CheckSpec{Type: "apparmor_runtime", Target: "current-kernel", Operator: "eq", Expected: appArmorReference, TimeoutMs: 5000}
}
func appArmorJSON() string {
	raw, _ := json.Marshal(map[string]any{"type": "apparmor_runtime", "target": "current-kernel", "operator": "eq", "expected": appArmorReference, "timeout_ms": 5000})
	return string(raw)
}
func goodAppArmorSnapshot() appArmorSnapshot {
	return appArmorSnapshot{Values: map[string]string{"enabled": "Y\n", "lsm": "capability,yama,apparmor,bpf", "mode": "enforce", "level": "0\n", "stacked": "no\n", "ns_stacked": "no\n", "profiles": "/usr/bin/example (enforce)\nexample//child (enforce)\n"}, Identities: map[string]string{"profiles": "kernel-identity"}}
}

func TestAppArmorDefinitionBoundary(t *testing.T) {
	var doc map[string]any
	json.Unmarshal([]byte(appArmorJSON()), &doc)
	if _, err := ParseCheck(appArmorJSON()); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]any{"target": "/etc/apparmor.d", "expected": "enforce", "operator": "contains", "timeout_ms": 0, "option": nil, "cmd": nil, "connection": nil, "profiles": nil, "namespace": nil} {
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
	for _, value := range []any{nil, 99, 30001, 100.5} {
		doc["timeout_ms"] = value
		raw, _ := json.Marshal(doc)
		if _, err := ParseCheck(string(raw)); err == nil {
			t.Fatal("invalid timeout", value)
		}
	}
	delete(doc, "timeout_ms")
	raw, _ := json.Marshal(doc)
	if s, err := ParseCheck(string(raw)); err != nil || s.TimeoutMs != 5000 {
		t.Fatal(s, err)
	}
	if runtime.GOOS == "windows" {
		r := checkOne(&pb.BaselineCheckSpec{ItemId: "apparmor-windows", Check: appArmorJSON()})
		if !r.Error || r.Passed || r.ItemID != "apparmor-windows" {
			t.Fatal(r)
		}
	}
}

func TestAppArmorRuntimeStatesAndRedaction(t *testing.T) {
	for _, tc := range []struct {
		name, key, value string
		pass, errorWant  bool
	}{
		{"all_enforce", "mode", "enforce", true, false},
		{"all_enforce_with_parameter_newline", "mode", "enforce\n", true, false},
		{"global_complain", "mode", "complain", false, false},
		{"global_kill", "mode", "kill", false, false},
		{"global_unconfined", "mode", "unconfined", false, false},
		{"empty", "profiles", "", false, false},
		{"one_complain", "profiles", "first (enforce)\nprivate-secret-profile (complain)\n", false, false},
		{"kill", "profiles", "private-secret-profile (kill)\n", false, false},
		{"unconfined", "profiles", "private-secret-profile (unconfined)\n", false, false},
		{"nested", "level", "1\n", false, true},
		{"stacked", "stacked", "yes\n", false, true},
		{"namespace_stack", "ns_stacked", "yes\n", false, true},
		{"unknown_global", "mode", "private-secret-mode", false, true},
		{"unknown_enabled", "enabled", "true\n", false, true},
		{"unknown_profile", "profiles", "private-secret-profile (prompt)\n", false, true},
		{"namespace", "profiles", ":child:private-secret-profile (enforce)\n", false, true},
		{"truncated", "profiles", "private-secret-profile (enforce)", false, true},
		{"duplicate", "profiles", "private-secret-profile (enforce)\nprivate-secret-profile (enforce)\n", false, true},
		{"lsm_duplicate", "lsm", "apparmor,apparmor", false, true},
		{"enabled_inconsistent", "enabled", "N\n", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := goodAppArmorSnapshot()
			s.Values[tc.key] = tc.value
			r := evaluateAppArmor(s)
			if r.Passed != tc.pass || r.Error != tc.errorWant || strings.Contains(r.Actual+r.Message, "private-secret") || !strings.Contains(r.Actual, "effective_access_state=unverified") {
				t.Fatal(r)
			}
		})
	}
	for _, enabled := range []string{"Y\n", "N\n"} {
		s := appArmorSnapshot{Values: map[string]string{"enabled": enabled, "lsm": "capability,yama"}}
		if r := evaluateAppArmor(s); r.Passed || r.Error || !strings.Contains(r.Actual, "profiles=not_observed") {
			t.Fatal(r)
		}
	}
}

func TestAppArmorInventoryLimits(t *testing.T) {
	for _, raw := range []string{"a (enforce)\n\n", "a (enforce)\r\n", "a//&b (enforce)\n", "a\\b (enforce)\n", "a\x00b (enforce)\n", "a (fake) (enforce)\n", "a (mixed)\n", "unconfined\n", " a (enforce)\n", "策略 (enforce)\n", strings.Repeat("x", 1024) + " (enforce)\n", strings.Repeat("x", appArmorMaxBytes+1)} {
		if _, err := parseAppArmorProfiles(raw); err == nil {
			t.Fatal("accepted unknown inventory")
		}
	}
	var raw strings.Builder
	for i := 0; i < appArmorMaxProfiles; i++ {
		fmt.Fprintf(&raw, "profile-%04d (enforce)\n", i)
	}
	if p, err := parseAppArmorProfiles(raw.String()); err != nil || len(p) != appArmorMaxProfiles {
		t.Fatal(len(p), err)
	}
	raw.WriteString("extra (enforce)\n")
	if _, err := parseAppArmorProfiles(raw.String()); err == nil {
		t.Fatal("profile count limit")
	}
	for _, raw := range []string{"", "apparmor\n", "apparmor,", "apparmor\nextra\n", "apparmor,private secret", "apparmor,apparmor", "apparmor\r", "apparmor\x00", strings.Repeat("x", 1025)} {
		if _, err := appArmorLSM(raw); err == nil {
			t.Fatal("LSM syntax")
		}
	}
	for raw, want := range map[string]bool{"apparmor": true, "capability,apparmor": true, "capability,yama": false} {
		if present, err := appArmorLSM(raw); err != nil || present != want {
			t.Fatal("complete EOF-terminated LSM inventory", present, err)
		}
	}
	names := make([]string, 32)
	for i := range names {
		names[i] = fmt.Sprintf("lsm%d", i)
	}
	if _, err := appArmorLSM(strings.Join(names, ",")); err != nil {
		t.Fatal("LSM count boundary", err)
	}
	if _, err := appArmorLSM(strings.Join(append(names, "extra"), ",")); err == nil {
		t.Fatal("LSM count limit")
	}
}

func TestAppArmorChangesFailuresAndDeadline(t *testing.T) {
	spec := appArmorSpec()
	for _, key := range []string{"profiles", "mode", "identity"} {
		calls := 0
		r := observeAppArmor(context.Background(), &spec, func() (appArmorSnapshot, error) {
			calls++
			s := goodAppArmorSnapshot()
			if calls == 2 {
				if key == "identity" {
					s.Identities["profiles"] = "changed"
				} else if key == "profiles" {
					s.Values[key] = "changed-name (enforce)\n"
				} else {
					s.Values[key] = "complain"
				}
			}
			return s, nil
		})
		if !r.Error || r.Passed || calls != 2 {
			t.Fatal(key, r, calls)
		}
	}
	r := observeAppArmor(context.Background(), &spec, func() (appArmorSnapshot, error) { return goodAppArmorSnapshot(), fmt.Errorf("private-secret-reader") })
	if !r.Error || strings.Contains(r.Actual+r.Message, "private-secret") {
		t.Fatal(r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	r = observeAppArmor(ctx, &spec, func() (appArmorSnapshot, error) { calls++; cancel(); return goodAppArmorSnapshot(), nil })
	if !r.Error || calls != 1 {
		t.Fatal(r, calls)
	}
	r = observeAppArmor(context.Background(), &spec, func() (appArmorSnapshot, error) { return goodAppArmorSnapshot(), nil })
	if r.Error || !r.Passed {
		t.Fatal(r)
	}
}
