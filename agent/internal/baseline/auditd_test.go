package baseline

import (
	"encoding/json"
	"runtime"
	"testing"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func auditdSpec(option string) *CheckSpec {
	return &CheckSpec{Type: "auditd_config", Target: "/etc/audit/auditd.conf", Option: option,
		Operator: "eq", Expected: auditdReference(option), TimeoutMs: 1000}
}

func TestAuditdDefinitionBoundary(t *testing.T) {
	for _, option := range []string{"local_logging", "keep_logs", "log_file_metadata"} {
		raw, _ := json.Marshal(auditdSpec(option))
		// Only the type-specific fields belong to the wire definition.
		var fields map[string]any
		json.Unmarshal(raw, &fields)
		for _, key := range []string{"regex", "cmd", "perm", "owner", "group", "connection"} {
			delete(fields, key)
		}
		valid, _ := json.Marshal(fields)
		if _, err := ParseCheck(string(valid)); err != nil {
			t.Fatal(err)
		}
		for key, value := range map[string]any{"target": "/tmp/auditd.conf", "operator": "regex", "expected": "yes", "option": "any", "cmd": nil, "owner": nil, "connection": nil} {
			changed := map[string]any{}
			for k, v := range fields {
				changed[k] = v
			}
			changed[key] = value
			bad, _ := json.Marshal(changed)
			if _, err := ParseCheck(string(bad)); err == nil {
				t.Fatalf("accepted %s", bad)
			}
		}
		if runtime.GOOS == "windows" {
			if r := checkOne(&pb.BaselineCheckSpec{ItemId: "auditd", Check: string(valid)}); !r.Error || r.Passed {
				t.Fatal(r)
			}
		}
	}
}
