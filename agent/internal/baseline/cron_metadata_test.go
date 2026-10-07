package baseline

import (
	"encoding/json"
	"runtime"
	"testing"
)

func cronSpec() *CheckSpec {
	return &CheckSpec{Type: "debian_cron_metadata", Target: "system-tables", Operator: "eq", Expected: cronMetadataReference, TimeoutMs: 1000}
}

func TestCronMetadataDefinitionBoundary(t *testing.T) {
	valid := map[string]any{"type": "debian_cron_metadata", "target": "system-tables", "operator": "eq", "expected": cronMetadataReference}
	for key, value := range map[string]any{"target": "/etc/crontab", "operator": "subset", "expected": "uid=0", "cmd": nil, "option": "any", "perm": "0644", "owner": "0", "group": "0", "uid_min": 1, "connection": nil} {
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
		if result := checkCronMetadata(cs); !result.Error || result.Passed {
			t.Fatalf("Linux type executed on Windows: %+v", result)
		}
	}
}
