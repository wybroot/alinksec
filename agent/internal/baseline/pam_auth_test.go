package baseline

import (
	"encoding/json"
	"runtime"
	"testing"
)

func TestPAMAuthDefinitionRejectsChangedScopeAndExecutionFields(t *testing.T) {
	doc := map[string]any{"type": "pam_auth", "target": "/etc/pam.d/login", "option": "faillock", "operator": "eq", "expected": pamLockoutReference}
	raw, _ := json.Marshal(doc)
	if _, err := ParseCheck(string(raw)); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"target", "option", "operator", "expected", "cmd", "connection", "regex", "uid_min", "config", "service"} {
		bad := map[string]any{}
		for key, value := range doc {
			bad[key] = value
		}
		bad[field] = "unreviewed"
		raw, _ := json.Marshal(bad)
		if _, err := ParseCheck(string(raw)); err == nil {
			t.Fatalf("accepted changed %s", field)
		}
	}
	if _, err := ParseCheck(`{"type":"pam_auth","target":"/etc/pam.d/login","option":"faillock","operator":"eq","expected":"` + pamLockoutReference + `","cmd":null}`); err == nil {
		t.Fatal("accepted empty execution field")
	}
}

func TestPAMAuthDoesNotExecuteOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows boundary")
	}
	if result := checkPAMAuth(&CheckSpec{Type: "pam_auth"}); !result.Error || result.Passed {
		t.Fatalf("unsupported platform passed: %+v", result)
	}
}
