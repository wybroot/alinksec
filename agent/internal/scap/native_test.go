package scap

import (
	"context"
	"encoding/json"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNativeScapWorker(t *testing.T) {
	if os.Getenv("ALINKSEC_SCAP_NATIVE_WORKER_REQUIRED") != "true" {
		t.Skip("requires the pinned native runtime and disposable standards fixture")
	}
	dir := filepath.Dir(os.Getenv("ALINKSEC_SCAP_TEST_BIN"))
	pin := os.Getenv("ALINKSEC_SCAP_TEST_RUNTIME_SHA256")
	archive, err := os.ReadFile(os.Getenv("ALINKSEC_SCAP_FIXTURE_ZIP"))
	if err != nil {
		t.Fatal(err)
	}
	content, err := ParseContent(archive)
	if err != nil {
		t.Fatal(err)
	}
	client := New(Config{Enabled: true, RuntimeDir: dir, RuntimeSHA256: pin, TimeoutSec: 180}, t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	if err = client.Probe(ctx); err != nil {
		t.Fatalf("actual bounded native identity: %v", err)
	}
	if client.Status().Version != "5.15" || client.Status().RuntimeSHA256 != pin || client.Status().State != "ready" {
		t.Fatal("native identity not bound to pin")
	}
	command := &pb.CmdScapScan{TaskId: "native-worker-fixture", ExecutionContract: 1, ContentZip: archive, ContentSha256: content.SHA256, BenchmarkId: content.Manifest.BenchmarkID, ProfileId: content.Manifest.ProfileID, RuntimeSha256: pin}
	result := client.Scan(ctx, "native-worker-command", command)
	record := map[string]any{"evidenceKind": "actual Agent bounded SCC worker with disposable host file; no remediation", "result": result, "status": client.Status()}
	if file := os.Getenv("ALINKSEC_SCAP_NATIVE_EVIDENCE_FILE"); file != "" {
		if err = os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			t.Fatal(err)
		}
		data, _ := json.MarshalIndent(record, "", "  ")
		if err = os.WriteFile(file, append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if result.State != "complete" || result.Issue != "" || !validHash(result.SourceResultSha256) || len(result.Rules) != 5 || len(result.Scores) == 0 {
		t.Fatalf("actual production worker did not complete: %+v", result)
	}
	expected := map[string]string{"xccdf_org.alinksec_rule_external": "pass", "xccdf_org.alinksec_rule_failure": "fail", "xccdf_org.alinksec_rule_compound": "pass", "xccdf_org.alinksec_rule_unselected": "notselected", "xccdf_org.alinksec_rule_platform": "notapplicable"}
	for _, rule := range result.Rules {
		if expected[rule.RuleId] != rule.Result {
			t.Fatalf("native worker coerced standard semantics: %+v", rule)
		}
	}
	if result.RuntimeSha256 != pin || result.ContentSha256 != content.SHA256 || result.ProfileId != content.Manifest.ProfileID {
		t.Fatal("native worker execution identity differs")
	}
	// A command cannot substitute a different locally installed runtime.
	command.RuntimeSha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	invalid := client.Scan(ctx, "different-runtime-command", command)
	if invalid.State != "failed" || invalid.Issue != "scap_command_invalid" || len(invalid.Rules) != 0 {
		t.Fatal("command replaced runtime pin")
	}
}
