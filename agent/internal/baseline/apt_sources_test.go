package baseline

import (
	"encoding/json"
	"runtime"
	"testing"
)

func aptSourcesSpec() *CheckSpec {
	return &CheckSpec{Type: "apt_sources_policy", Target: "/etc/apt", Operator: "eq", Expected: aptSourcesReference, TimeoutMs: 1000}
}
func TestAPTSourcesDefinitionBoundary(t *testing.T) {
	valid := map[string]any{"type": "apt_sources_policy", "target": "/etc/apt", "operator": "eq", "expected": aptSourcesReference}
	for key, value := range map[string]any{"target": "/tmp/apt", "operator": "regex", "expected": "trusted=false", "cmd": nil, "option": nil, "perm": "0644", "uid_min": 0, "connection": nil} {
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
		if r := checkAPTSources(cs); !r.Error || r.Passed {
			t.Fatalf("Linux check executed: %+v", r)
		}
	}
}
