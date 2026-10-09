package baseline

import (
	"encoding/json"
	"runtime"
	"testing"
)

func shadowDefaultsSpec(option string) CheckSpec {
	s := CheckSpec{Type: "shadow_account_defaults", Target: shadowDefaultsTarget, Option: option, Operator: "eq", Expected: shadowMaxReference, TimeoutMs: 1000}
	if option == "warn_days" {
		s.Expected = shadowWarnReference
	}
	return s
}

func shadowDefaultsJSON(s CheckSpec) string {
	b, _ := json.Marshal(map[string]any{"type": s.Type, "target": s.Target, "option": s.Option, "operator": s.Operator, "expected": s.Expected, "timeout_ms": s.TimeoutMs})
	return string(b)
}

func TestShadowDefaultsDefinitionBoundary(t *testing.T) {
	for _, option := range []string{"max_days", "warn_days"} {
		s := shadowDefaultsSpec(option)
		if _, err := ParseCheck(shadowDefaultsJSON(s)); err != nil {
			t.Fatal(err)
		}
		for _, mutate := range []func(*CheckSpec){
			func(s *CheckSpec) { s.Target = "/etc/shadow" }, func(s *CheckSpec) { s.Option = "min_days" },
			func(s *CheckSpec) { s.Operator = "regex" }, func(s *CheckSpec) { s.Expected = "90" },
			func(s *CheckSpec) { s.TimeoutMs = 0 },
		} {
			bad := s
			mutate(&bad)
			if _, err := ParseCheck(shadowDefaultsJSON(bad)); err == nil {
				t.Fatalf("unsafe definition accepted: %+v", bad)
			}
		}
		var document map[string]any
		json.Unmarshal([]byte(shadowDefaultsJSON(s)), &document)
		for _, field := range []string{"cmd", "regex", "connection", "uid_min", "uid_max", "perm", "owner", "group"} {
			document[field] = nil
			b, _ := json.Marshal(document)
			if _, err := ParseCheck(string(b)); err == nil {
				t.Fatal("unsupported null field accepted:", field)
			}
			delete(document, field)
		}
		document["timeout_ms"] = nil
		b, _ := json.Marshal(document)
		if _, err := ParseCheck(string(b)); err == nil {
			t.Fatal("explicit null timeout accepted")
		}
	}
}

func TestShadowDefaultsDoesNotExecuteOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows boundary")
	}
	s := shadowDefaultsSpec("max_days")
	if r := checkShadowAccountDefaults(&s); !r.Error || r.Passed {
		t.Fatalf("Linux product executed on Windows: %+v", r)
	}
}
