package baseline

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func noticeTestSpec(option string) CheckSpec {
	s := CheckSpec{Type: "sshd_notice", Target: sshNoticeTarget, Option: option, Operator: "eq", Expected: "no", TimeoutMs: 1000,
		Connection: &SSHConnection{User: "root", Host: "admin.example.invalid", Address: "192.0.2.10", LocalAddress: "192.0.2.20", LocalPort: 22}}
	if option == "banner" {
		s.Expected = "file=" + sshNoticeBanner + ",sha256=" + strings.Repeat("a", 64)
	}
	return s
}

func noticeJSON(s CheckSpec) string {
	data, _ := json.Marshal(map[string]any{"type": s.Type, "target": s.Target, "option": s.Option, "connection": s.Connection, "operator": s.Operator, "expected": s.Expected, "timeout_ms": s.TimeoutMs})
	return string(data)
}

func TestSSHNoticeDefinitionBoundary(t *testing.T) {
	for _, option := range []string{"usedns", "banner"} {
		valid := noticeTestSpec(option)
		if _, err := ParseCheck(noticeJSON(valid)); err != nil {
			t.Fatal(err)
		}
		for _, change := range []func(*CheckSpec){
			func(s *CheckSpec) { s.Target = "/tmp/sshd_config" }, func(s *CheckSpec) { s.Option = "permitrootlogin" },
			func(s *CheckSpec) { s.Operator = "regex" }, func(s *CheckSpec) { s.Expected = "yes" },
			func(s *CheckSpec) { s.Connection = nil }, func(s *CheckSpec) { s.Expected = "file=/etc/shadow,sha256=" + strings.Repeat("a", 64) },
			func(s *CheckSpec) { s.Expected = "file=" + sshNoticeBanner + ",sha256=" + strings.Repeat("A", 64) },
			func(s *CheckSpec) { s.TimeoutMs = 0 },
		} {
			s := valid
			change(&s)
			if _, err := ParseCheck(noticeJSON(s)); err == nil {
				t.Fatalf("invalid notice accepted: %s", noticeJSON(s))
			}
		}
		for _, extra := range []string{`"cmd":null,`, `"uid_min":null,`, `"regex":"",`, `"perm":"",`} {
			if _, err := ParseCheck("{" + extra + noticeJSON(valid)[1:]); err == nil {
				t.Fatalf("extension accepted: %s", extra)
			}
		}
		for _, raw := range []string{
			strings.Replace(noticeJSON(valid), `"timeout_ms":1000`, `"timeout_ms":null`, 1),
			strings.Replace(noticeJSON(valid), `"user":"root"`, `"user":"root","user":"other"`, 1),
			strings.Replace(noticeJSON(valid), `"user":"root"`, `"extra":"flag","user":"root"`, 1),
		} {
			if _, err := ParseCheck(raw); err == nil {
				t.Fatal("duplicate/unknown connection accepted")
			}
		}
	}
}

func TestSSHNoticeDoesNotExecuteOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows boundary")
	}
	result := checkSSHNotice(&CheckSpec{Type: "sshd_notice"})
	if !result.Error || result.Passed {
		t.Fatalf("Windows notice must error: %+v", result)
	}
}
