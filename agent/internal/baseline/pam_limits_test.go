package baseline

import (
	"encoding/json"
	"runtime"
	"testing"
)

func TestPAMLimitsDefinitionBoundary(t *testing.T) {
	for _, option := range []string{"core", "nofile", "nproc"} {
		doc := map[string]any{"type": "pam_limits", "target": "/etc/pam.d/login", "option": option, "operator": "eq", "expected": pamLimitsReference(option), "timeout_ms": 1000}
		raw, _ := json.Marshal(doc)
		if _, err := ParseCheck(string(raw)); err != nil {
			t.Fatal(err)
		}
		for key, value := range map[string]any{"target": "/etc/security/limits.conf", "operator": "contains", "expected": "0", "option": "memlock", "cmd": nil, "uid_min": 1000, "connection": nil} {
			changed := map[string]any{}
			for k, v := range doc {
				changed[k] = v
			}
			changed[key] = value
			raw, _ := json.Marshal(changed)
			if _, err := ParseCheck(string(raw)); err == nil {
				t.Fatalf("accepted weakened definition %s", key)
			}
		}
	}
}

func TestPAMLimitsDoesNotExecuteOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows boundary")
	}
	if result := checkPAMLimits(&CheckSpec{Type: "pam_limits"}); !result.Error || result.Passed {
		t.Fatalf("unsupported platform passed: %+v", result)
	}
}
