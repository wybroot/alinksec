package baseline

import (
	"encoding/json"
	"runtime"
	"testing"
)

func TestLogMetadataDefinitionBoundary(t *testing.T) {
	valid := map[string]any{"type": "linux_log_metadata", "target": "/var/log/btmp", "operator": "subset", "perm": "0660", "owner": "0", "group": "utmp"}
	for key, value := range map[string]any{"target": "/tmp/btmp", "perm": "0666", "owner": "root", "group": "0", "operator": "eq", "cmd": nil, "option": "anything", "expected": "", "uid_min": 1, "connection": nil} {
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
	for _, target := range []string{"/var/log/audit", "/var/log/btmp", "/var/log/wtmp"} {
		perm, group := logMetadataPolicy(target)
		valid["target"], valid["perm"], valid["group"] = target, perm, group
		raw, _ := json.Marshal(valid)
		cs, err := ParseCheck(string(raw))
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS == "windows" {
			if result := checkLogMetadata(cs); !result.Error || result.Passed {
				t.Fatalf("Linux type executed on Windows: %+v", result)
			}
		}
	}
}
