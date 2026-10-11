package baseline

import (
	"encoding/json"
	"testing"
)

func dnfSpec() *CheckSpec {
	return &CheckSpec{Type: "dnf_signature_policy", Target: "/etc/dnf/dnf.conf", Operator: "eq", Expected: dnfSignatureReference, TimeoutMs: 1000}
}
func TestDNFSignatureDefinitionBoundary(t *testing.T) {
	doc := map[string]any{"type": "dnf_signature_policy", "target": "/etc/dnf/dnf.conf", "operator": "eq", "expected": dnfSignatureReference}
	raw, _ := json.Marshal(doc)
	if _, err := ParseCheck(string(raw)); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"option", "cmd", "repo", "reposdir", "connection", "root", "key", "timeout_ms"} {
		bad := map[string]any{}
		for k, v := range doc {
			bad[k] = v
		}
		bad[field] = nil
		raw, _ := json.Marshal(bad)
		if _, err := ParseCheck(string(raw)); err == nil {
			t.Fatal(field)
		}
	}
}
