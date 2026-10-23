//go:build linux || windows

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/config"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/virusscan"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"
)

func TestNativeEvidenceAgent(t *testing.T) {
	binary := os.Getenv("ALINKSEC_EVIDENCE_AGENT_BIN")
	if binary == "" {
		t.Skip("requires an actual native Agent and harmless quarantine fixture")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("absolute Agent binary required")
	}
	root := t.TempDir()
	fixture, address, ca := newSCMFixture(t, root)
	work := filepath.Join(root, "Evidence Agent Work With Spaces")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, binary, "install", "--server", address, "--token", "ENROLL-windows-scm-fixture", "--ca-file", ca, "--workdir", work).CombinedOutput(); err != nil {
		t.Fatalf("install %v %s", err, out)
	}
	cfg, err := config.Load(filepath.Join(work, "agent.yml"))
	if err != nil {
		t.Fatal(err)
	}
	disabled := false
	cfg.Decoy = config.DecoyConfig{Enabled: &disabled, Response: "alert_only"}
	cfg.HeartbeatInterval = time.Second
	cfg.CollectInterval = 24 * time.Hour
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	applyNativeConfig(t, binary, work, data)
	sample := []byte("Harmless actual native central evidence fixture\n")
	original := filepath.Join(root, "harmless evidence sample.bin")
	if err := os.WriteFile(original, sample, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(sample)
	hash := hex.EncodeToString(sum[:])
	quarantine := virusscan.NewQuarantine(work)
	capture, err := quarantine.QuarantineExpected(context.Background(), original, hash)
	if err != nil {
		t.Fatal(err)
	}
	process := &configProcess{binary: binary, work: work}
	process.start(t)
	defer process.stop(t)
	connection := fixture.nextConnection(t)
	ready := func() {
		fixture.awaitReport(t, connection.number, func(report *pb.Report) bool { return report.GetHeartbeat().GetEvidenceContract() == 1 })
	}
	ready()
	fixture.awaitReport(t, connection.number, func(report *pb.Report) bool { return report.GetAsset() != nil })
	request := &pb.CmdEvidenceCollect{RequestId: "11111111-1111-4111-8111-111111111111", ExecutionContract: 1, Kind: "diagnostic", Deadline: time.Now().Add(10 * time.Minute).UnixMilli()}
	command := &pb.Command{CmdId: "22222222-2222-4222-8222-222222222222", IssuedAt: time.Now().UnixMilli(), Payload: &pb.Command_EvidenceCollect{EvidenceCollect: request}}
	connection.commands <- command
	report := fixture.awaitReport(t, connection.number, func(report *pb.Report) bool { return report.GetEvidence().GetRequestId() == request.RequestId })
	result := report.GetEvidence()
	if result.ErrorCode != "" || result.ExecutionContract != 1 || result.Kind != "diagnostic" || len(result.Content) == 0 || len(result.Content) > 1<<20 || result.CommandId != command.CmdId {
		t.Fatal(result)
	}
	digest := sha256.Sum256(result.Content)
	if result.Sha256 != hex.EncodeToString(digest[:]) {
		t.Fatal("native diagnostic digest mismatch")
	}
	archive, err := zip.NewReader(bytes.NewReader(result.Content), int64(len(result.Content)))
	if err != nil || len(archive.File) != 3 {
		t.Fatal("invalid native diagnostic ZIP", err)
	}
	fixture.awaitReport(t, connection.number, func(report *pb.Report) bool {
		return report.GetAck().GetCmdId() == command.CmdId && report.GetAck().GetStage() == pb.RptAck_DONE
	})
	// Deliberately lose the application receipt, terminate the real process and
	// require the same collected bytes on the newly authenticated connection.
	process.stop(t)
	process.start(t)
	connection = fixture.nextConnection(t)
	ready()
	fixture.awaitReport(t, connection.number, func(report *pb.Report) bool { return report.GetAsset() != nil })
	replayed := fixture.awaitReport(t, connection.number, func(report *pb.Report) bool { return report.GetEvidence().GetRequestId() == request.RequestId })
	if !proto.Equal(report, replayed) {
		t.Fatal("native restart recollected or changed pending evidence")
	}
	connection.commands <- command
	fixture.awaitReport(t, connection.number, func(report *pb.Report) bool {
		return report.GetAck().GetCmdId() == command.CmdId && report.GetAck().GetStage() == pb.RptAck_DONE
	})
	connection.commands <- &pb.Command{Payload: &pb.Command_EvidenceReceipt{EvidenceReceipt: &pb.CmdEvidenceReceipt{RequestId: request.RequestId, CommandId: command.CmdId, ContentSha256: result.Sha256}}}
	awaitReceipt := func() {
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			content, err := os.ReadFile(filepath.Join(work, "evidence-state", "pending.json"))
			var state struct {
				Schema  int
				Records []json.RawMessage
			}
			if err == nil && json.Unmarshal(content, &state) == nil && state.Schema == 1 && len(state.Records) == 0 {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("native Agent did not persist the committed evidence receipt")
	}
	awaitReceipt()
	sampleRequest := &pb.CmdEvidenceCollect{RequestId: "33333333-3333-4333-8333-333333333333", ExecutionContract: 1, Kind: "quarantine_sample", Deadline: time.Now().Add(time.Minute).UnixMilli(), QuarantineId: capture, OriginalPath: original, ExpectedSha256: hash}
	sampleCommand := &pb.Command{CmdId: "44444444-4444-4444-8444-444444444444", IssuedAt: time.Now().UnixMilli(), Payload: &pb.Command_EvidenceCollect{EvidenceCollect: sampleRequest}}
	connection.commands <- sampleCommand
	sampleResponse := fixture.awaitReport(t, connection.number, func(report *pb.Report) bool {
		return report.GetEvidence().GetRequestId() == sampleRequest.RequestId || report.GetAck().GetCmdId() == sampleCommand.CmdId && report.GetAck().GetStage() == pb.RptAck_FAILED
	})
	if sampleResponse.GetAck() != nil {
		t.Fatalf("native sample request failed: %s", sampleResponse.GetAck().GetMessage())
	}
	sampleReport := sampleResponse.GetEvidence()
	if sampleReport.ErrorCode != "" || sampleReport.Sha256 != hash || !bytes.Equal(sampleReport.Content, sample) {
		t.Fatal("native sample export differs", sampleReport)
	}
	retained, err := quarantine.ExportExpected(context.Background(), original, capture, hash, 1<<20)
	if err != nil || !bytes.Equal(retained, sample) {
		t.Fatal("export changed native quarantine state", err)
	}
	if _, err := os.Stat(original); !os.IsNotExist(err) {
		t.Fatal("sample export restored original path")
	}
	connection.commands <- &pb.Command{Payload: &pb.Command_EvidenceReceipt{EvidenceReceipt: &pb.CmdEvidenceReceipt{RequestId: sampleRequest.RequestId, CommandId: sampleCommand.CmdId, ContentSha256: hash}}}
	awaitReceipt()
	if output := os.Getenv("ALINKSEC_EVIDENCE_NATIVE_OUTPUT"); output != "" {
		if err := os.MkdirAll(output, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(output, "diagnostic.zip"), result.Content, 0600); err != nil {
			t.Fatal(err)
		}
		checks := []string{"verified_enrollment_and_mtls", "fixed_diagnostic_zip_and_digest", "actual_process_restart_replays_identical_file", "duplicate_command_uses_retained_file", "committed_receipt_persisted", "native_quarantine_capture_bytes_and_digest", "export_preserves_quarantine"}
		proof, _ := json.MarshalIndent(map[string]any{"passed": true, "os": runtime.GOOS, "arch": runtime.GOARCH, "checks": checks, "diagnosticBytes": len(result.Content), "diagnosticSha256": result.Sha256, "sampleBytes": len(sample), "sampleSha256": hash}, "", "  ")
		if err := os.WriteFile(filepath.Join(output, "result.json"), proof, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
