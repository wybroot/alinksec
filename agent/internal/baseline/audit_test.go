package baseline

import (
	"runtime"
	"testing"
)

func TestAuditDoesNotExecuteOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows boundary")
	}
	if r := checkLinuxAudit(&CheckSpec{Option: "enabled"}); !r.Error || r.Passed {
		t.Fatal(r)
	}
}

func TestAuditCheckDefinitionBoundary(t *testing.T) {
	for _, option := range []string{"enabled", "identity_watches"} {
		base := `{"type":"linux_audit","target":"kernel","option":"` + option + `","operator":"eq","expected":"` + auditReference(option) + `"`
		if _, err := ParseCheck(base + `}`); err != nil {
			t.Fatal(err)
		}
		for _, extra := range []string{`,"cmd":null`, `,"connection":null`, `,"perm":"0777"`, `,"owner":"root"`, `,"regex":".*"`, `,"uid_min":null`, `,"option":"enabled"`} {
			if _, err := ParseCheck(base + extra + `}`); err == nil {
				t.Fatalf("accepted extra/duplicate field %s", extra)
			}
		}
	}
	for _, raw := range []string{
		`{"type":"linux_audit","target":"/etc/passwd","option":"enabled","operator":"eq","expected":"enabled=1|2"}`,
		`{"type":"linux_audit","target":"kernel","option":"any","operator":"eq","expected":""}`,
		`{"type":"linux_audit","target":"kernel","option":"identity_watches","operator":"eq","expected":"wa"}`,
		`{"type":"linux_audit","target":"kernel","option":"enabled","operator":"regex","expected":"enabled=1|2"}`,
	} {
		if _, err := ParseCheck(raw); err == nil {
			t.Fatal("accepted weakened/redirected reference", raw)
		}
	}
}
