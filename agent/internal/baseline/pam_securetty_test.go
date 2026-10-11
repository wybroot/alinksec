package baseline

import (
	"encoding/json"
	"runtime"
	"testing"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func TestSecureTTYDefinitionBoundary(t *testing.T) {
	doc := map[string]any{"type": "pam_securetty", "target": "/etc/pam.d/login", "operator": "eq", "expected": pamSecureTTYReference}
	raw, _ := json.Marshal(doc)
	if _, err := ParseCheck(string(raw)); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "linux" {
		r := checkOne(&pb.BaselineCheckSpec{ItemId: "securetty-platform", Check: string(raw)})
		if !r.Error || r.Passed || r.ItemID != "securetty-platform" {
			t.Fatal(r)
		}
	}
	for _, field := range []string{"option", "cmd", "regex", "tty", "file", "connection", "namespace"} {
		bad := map[string]any{}
		for k, v := range doc {
			bad[k] = v
		}
		bad[field] = nil
		raw, _ := json.Marshal(bad)
		if _, err := ParseCheck(string(raw)); err == nil {
			t.Fatalf("expanded %s", field)
		}
	}
	for _, timeout := range []any{nil, 0, 99, 30001, "5000"} {
		doc["timeout_ms"] = timeout
		raw, _ := json.Marshal(doc)
		if _, err := ParseCheck(string(raw)); err == nil {
			t.Fatalf("timeout %v", timeout)
		}
	}
}
