package baseline

import (
	"encoding/json"
	"runtime"
	"testing"
)

func sudoersSpec(option string) *CheckSpec {
	return &CheckSpec{Type: "sudoers_policy", Target: "/etc/sudoers", Option: option, Operator: "eq", Expected: sudoersReference(option), TimeoutMs: 1000}
}

func TestSudoersDefinitionBoundary(t *testing.T) {
	for _, option := range []string{"authentication", "allowed_logging"} {
		valid := map[string]any{"type": "sudoers_policy", "target": "/etc/sudoers", "option": option, "operator": "eq", "expected": sudoersReference(option)}
		for key, value := range map[string]any{"target": "/tmp/sudoers", "operator": "regex", "expected": "on", "cmd": nil, "option": "any", "perm": "0440", "owner": "0", "group": "0", "uid_min": 0, "connection": nil} {
			changed := map[string]any{}
			for k, v := range valid {
				changed[k] = v
			}
			changed[key] = value
			raw, _ := json.Marshal(changed)
			if _, err := ParseCheck(string(raw)); err == nil {
				t.Fatalf("accepted %s", raw)
			}
		}
		raw, _ := json.Marshal(valid)
		cs, err := ParseCheck(string(raw))
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS == "windows" {
			if r := checkSudoers(cs); !r.Error || r.Passed {
				t.Fatalf("Linux check executed on Windows: %+v", r)
			}
		}
	}
}
