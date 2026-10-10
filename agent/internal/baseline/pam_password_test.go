package baseline

import (
	"encoding/json"
	"runtime"
	"testing"
)

func TestPAMPasswordDefinitionRequiresFixedServiceAndReference(t *testing.T) {
	for _, option := range []string{"quality", "unix_hash"} {
		expected := pamQualityReference
		if option == "unix_hash" {
			expected = "yescrypt"
		}
		doc := map[string]any{"type": "pam_password", "target": "/etc/pam.d/passwd", "option": option, "operator": "eq", "expected": expected}
		raw, _ := json.Marshal(doc)
		if _, err := ParseCheck(string(raw)); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"cmd", "connection", "regex", "service", "uid_min", "modules", "config"} {
			bad := map[string]any{}
			for key, v := range doc {
				bad[key] = v
			}
			bad[field] = nil
			raw, _ := json.Marshal(bad)
			if _, err := ParseCheck(string(raw)); err == nil {
				t.Fatalf("accepted expanded field %s", field)
			}
		}
		for _, field := range []string{"target", "expected", "operator", "option"} {
			bad := map[string]any{}
			for key, v := range doc {
				bad[key] = v
			}
			bad[field] = "unreviewed"
			raw, _ := json.Marshal(bad)
			if _, err := ParseCheck(string(raw)); err == nil {
				t.Fatalf("accepted changed %s", field)
			}
		}
	}
}

func TestPAMPasswordDoesNotExecuteOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows platform boundary")
	}
	if result := checkPAMPassword(&CheckSpec{Type: "pam_password"}); !result.Error || result.Passed {
		t.Fatalf("unsupported platform passed: %+v", result)
	}
}
