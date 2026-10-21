package scap

import (
	"context"
	"encoding/json"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestNativeScapWorker(t *testing.T) {
	if os.Getenv("ALINKSEC_SCAP_NATIVE_WORKER_REQUIRED") != "true" {
		t.Skip("requires the pinned native runtime and disposable standards fixture")
	}
	dir := filepath.Dir(os.Getenv("ALINKSEC_SCAP_TEST_BIN"))
	pin := os.Getenv("ALINKSEC_SCAP_TEST_RUNTIME_SHA256")
	manifestBytes, err := os.ReadFile(filepath.Join(dir, "alinksec-runtime.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest runtimeManifest
	if err = json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, file := range manifest.Files {
		if !safeRuntimePath(file.Path) {
			t.Fatalf("official runtime path is outside supported boundary: %q", file.Path)
		}
	}
	archive, err := os.ReadFile(os.Getenv("ALINKSEC_SCAP_FIXTURE_ZIP"))
	if err != nil {
		t.Fatal(err)
	}
	content, err := ParseContent(archive)
	if err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(t.TempDir(), "Agent Work With Spaces")
	if err := os.MkdirAll(work, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Enabled: true, RuntimeDir: dir, RuntimeSHA256: pin, TimeoutSec: 180}
	client := New(cfg, work)
	before, err := filepath.Glob(filepath.Join(nativeTempRoot(), "alinksec-scap-*"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	if err = client.Probe(ctx); err != nil {
		// Only the explicit native CI test prints this bounded version-only
		// diagnostic. Production errors and reports retain fixed issue codes.
		directory := filepath.Join(t.TempDir(), "runtime with spaces")
		if binary, cloneErr := cloneRuntime(ctx, cfg, directory); cloneErr == nil {
			if configErr := configureRuntime(directory, filepath.Join(t.TempDir(), "reports"), 180); configErr == nil {
				command := exec.CommandContext(ctx, binary, "--version")
				command.Dir = directory
				command.Env = cleanEnvironment()
				stdout, stderr := &cappedBuffer{limit: 16384}, &cappedBuffer{limit: 4096}
				command.Stdout = stdout
				command.Stderr = stderr
				err := command.Run()
				t.Logf("isolated version diagnostic without Job Object: error=%v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
			} else {
				t.Log("trusted template configuration:", configErr)
			}
		} else {
			t.Log("trusted runtime clone:", cloneErr)
		}
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
	cancelled, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer stop()
	failed := client.Scan(cancelled, "cancelled-native-command", command)
	if failed.State != "failed" || len(failed.Rules) != 0 || failed.SourceResultSha256 != "" {
		t.Fatal("cancelled worker fabricated evidence", failed)
	}
	if entries, err := os.ReadDir(work); err != nil || len(entries) != 0 {
		t.Fatal("native worker cancellation left a workspace", err, len(entries))
	}
	after, err := filepath.Glob(filepath.Join(nativeTempRoot(), "alinksec-scap-*"))
	if err != nil || !slices.Equal(before, after) {
		t.Fatal("native parent left a private temporary runtime", err, before, after)
	}
	// A command cannot substitute a different locally installed runtime.
	command.RuntimeSha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	invalid := client.Scan(ctx, "different-runtime-command", command)
	if invalid.State != "failed" || invalid.Issue != "scap_command_invalid" || len(invalid.Rules) != 0 {
		t.Fatal("command replaced runtime pin")
	}
}
