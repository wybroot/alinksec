package baseline

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func bashPolicySpec(option string) CheckSpec {
	return CheckSpec{Type: "bash_global_policy", Target: bashPolicyTarget, Option: option, Operator: "eq", Expected: bashPolicyReferences[option], TimeoutMs: 1000}
}
func bashPolicyJSON(s CheckSpec) string {
	b, _ := json.Marshal(map[string]any{"type": s.Type, "target": s.Target, "option": s.Option, "operator": s.Operator, "expected": s.Expected, "timeout_ms": s.TimeoutMs})
	return string(b)
}
func TestBashPolicyDefinitionBoundary(t *testing.T) {
	for option := range bashPolicyReferences {
		s := bashPolicySpec(option)
		if _, err := ParseCheck(bashPolicyJSON(s)); err != nil {
			t.Fatal(err)
		}
		for _, mutate := range []func(*CheckSpec){func(s *CheckSpec) { s.Target = "/root" }, func(s *CheckSpec) { s.Option = "arbitrary" }, func(s *CheckSpec) { s.Expected = "positive" }, func(s *CheckSpec) { s.Operator = "regex" }, func(s *CheckSpec) { s.TimeoutMs = 0 }} {
			bad := s
			mutate(&bad)
			if _, err := ParseCheck(bashPolicyJSON(bad)); err == nil {
				t.Fatal("unsafe definition accepted")
			}
		}
		var doc map[string]any
		json.Unmarshal([]byte(bashPolicyJSON(s)), &doc)
		for _, field := range []string{"cmd", "regex", "connection", "owner", "uid_min", "perm"} {
			doc[field] = nil
			b, _ := json.Marshal(doc)
			if _, err := ParseCheck(string(b)); err == nil {
				t.Fatal("unsupported null field", field)
			}
			delete(doc, field)
		}
		doc["timeout_ms"] = nil
		b, _ := json.Marshal(doc)
		if _, err := ParseCheck(string(b)); err == nil {
			t.Fatal("null timeout accepted")
		}
	}
}
func TestBashPolicyDoesNotExecuteOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows boundary")
	}
	s := bashPolicySpec("login_timeout")
	if r := checkBashGlobalPolicy(&s); !r.Error || r.Passed {
		t.Fatal(r)
	}
}
func TestBashFiniteDeclarationSemantics(t *testing.T) {
	for _, tc := range []struct {
		name, body                                      string
		timeout, mask, format, capacity, executionError bool
	}{
		{"approved", "export TMOUT=600\nreadonly TMOUT\numask 027\nHISTTIMEFORMAT='%F %T %z '\nHISTSIZE=1000\nHISTFILESIZE=10000\n", true, true, true, true, false},
		{"attributes_order", "export TMOUT\nreadonly TMOUT=1\numask 0077\n", true, true, false, false, false},
		{"no_readonly", "export TMOUT=600\n", false, false, false, false, false},
		{"no_export", "readonly TMOUT=600\n", false, false, false, false, false},
		{"zero_disabled", "export TMOUT=0\nreadonly TMOUT\nHISTSIZE=0\nHISTFILESIZE=-1\numask 000\n", false, false, false, false, false},
		{"outside", "export TMOUT=601\nreadonly TMOUT\nHISTSIZE=10001\nHISTFILESIZE=1000\n", false, false, false, false, false},
		{"last_wins", "TMOUT=0\nTMOUT=600\nexport TMOUT\nreadonly TMOUT\numask 022\numask 077\n", true, true, false, false, false},
		{"unset", "HISTSIZE=1000\nHISTFILESIZE=1000\nunset HISTSIZE HISTFILESIZE\n", false, false, false, false, false},
		{"redacted_format", "HISTTIMEFORMAT='DO_NOT_REPORT_SECRET'\n", false, false, false, false, false},
		{"readonly_override", "readonly TMOUT=600\nTMOUT=600\n", false, false, false, false, true},
		{"readonly_unset", "readonly TMOUT=600\nunset TMOUT\n", false, false, false, false, true},
		{"unknown_variable", "PATH=/tmp\n", false, false, false, false, true},
		{"unknown_command", "touch /tmp/must-not-execute\n", false, false, false, false, true},
		{"command_substitution", "TMOUT=$(id)\n", false, false, false, false, true},
		{"arithmetic", "TMOUT=$((600))\n", false, false, false, false, true},
		{"octal", "TMOUT=0600\n", false, false, false, false, true},
		{"overflow", "TMOUT=2147483648\n", false, false, false, false, true},
		{"unicode", "TMOUT\u00a0=600\n", false, false, false, false, true},
		{"inline_comment", "TMOUT=600 # hidden\n", false, false, false, false, true},
		{"quote_concat", "HISTTIMEFORMAT='a'\"b\"\n", false, false, false, false, true},
		{"conditional", "if true; then TMOUT=600; fi\n", false, false, false, false, true},
		{"redirect", "TMOUT=600 > /tmp/output\n", false, false, false, false, true},
		{"source", ". /etc/other\n", false, false, false, false, true},
		{"escape", "TMOUT=\\600\n", false, false, false, false, true},
		{"too_many", strings.Repeat("HISTSIZE=1000\n", 513), false, false, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newBashDeclarations()
			err := d.parse(tc.body)
			if (err != nil) != tc.executionError {
				t.Fatalf("classification: %v", err)
			}
			if err != nil {
				return
			}
			for option, want := range map[string]bool{"login_timeout": tc.timeout, "login_umask": tc.mask, "history_time": tc.format, "history_capacity": tc.capacity} {
				r := d.result(option)
				if r.Passed != want || strings.Contains(r.Actual+r.Message, "DO_NOT_REPORT_SECRET") {
					t.Fatal(option, r)
				}
			}
		})
	}
}
