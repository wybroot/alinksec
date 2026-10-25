//go:build linux || windows

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/config"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/securestate"
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
	observations := []evidenceReceiptObservation{}
	t.Cleanup(func() { retainEvidenceObservations(t, root, observations) })
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
	awaitReceipt := func(command *pb.Command) {
		t.Helper()
		started := time.Now()
		deadline := time.Now().Add(10 * time.Second)
		observation := evidenceReceiptObservation{CommandID: command.CmdId}
		defer func() {
			observation.ElapsedMillis = time.Since(started).Milliseconds()
			observations = append(observations, observation)
		}()
		encoded, err := proto.Marshal(command.GetEvidenceCollect())
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(encoded)
		expectedDigest := hex.EncodeToString(digest[:])
		for time.Now().Before(deadline) {
			observation.Polls++
			var state struct {
				Schema    int
				Records   []json.RawMessage
				Completed []struct {
					CommandID, CommandDigest string
					Failed                   bool
					ExpiresAt                int64
				}
			}
			// Ordinary os.ReadFile opens without FILE_SHARE_DELETE on Windows.
			// The observer must permit the Agent to atomically replace this path.
			err := securestate.ReadJSONLimit(filepath.Join(work, "evidence-state", "pending.json"), &state, 4<<20)
			if err != nil {
				observation.ReadErrors++
				observation.LastReadError = err.Error()
			} else {
				observation.PendingRecords = len(state.Records)
				for _, completed := range state.Completed {
					if state.Schema == 1 && len(state.Records) == 0 && completed.CommandID == command.CmdId && completed.CommandDigest == expectedDigest && !completed.Failed && completed.ExpiresAt > time.Now().UnixMilli() {
						observation.Committed = true
						return
					}
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("native Agent did not persist the committed evidence receipt: polls=%d read_errors=%d pending=%d last_read_error=%q", observation.Polls, observation.ReadErrors, observation.PendingRecords, observation.LastReadError)
	}
	awaitReceipt(command)
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
	awaitReceipt(sampleCommand)
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

type evidenceReceiptObservation struct {
	CommandID      string `json:"commandId"`
	Committed      bool   `json:"committed"`
	ElapsedMillis  int64  `json:"elapsedMillis"`
	Polls          int    `json:"polls"`
	ReadErrors     int    `json:"readErrors"`
	PendingRecords int    `json:"pendingRecords"`
	LastReadError  string `json:"lastReadError,omitempty"`
}

func retainEvidenceObservations(t *testing.T, root string, observations []evidenceReceiptObservation) {
	t.Helper()
	output := os.Getenv("ALINKSEC_EVIDENCE_NATIVE_OUTPUT")
	if output != "" {
		if err := os.MkdirAll(output, 0700); err != nil {
			t.Errorf("create evidence observations directory: %v", err)
			return
		}
		data, err := json.MarshalIndent(map[string]any{"passed": !t.Failed(), "receiptDeadlineMillis": 10000, "receipts": observations}, "", "  ")
		if err == nil {
			err = os.WriteFile(filepath.Join(output, "observations.json"), data, 0600)
		}
		if err != nil {
			t.Errorf("retain evidence observations: %v", err)
		}
	}
	if !t.Failed() {
		return
	}
	// Retain only the bounded output of this disposable fixture process. Never
	// copy agent.yml, credentials, raw journals or captured quarantine contents.
	f, err := os.Open(filepath.Join(root, "agent-process.log"))
	if err != nil {
		t.Logf("open failed evidence process log: %v", err)
		return
	}
	defer f.Close()
	if info, err := f.Stat(); err == nil && info.Size() > 64<<10 {
		if _, err := f.Seek(-(64 << 10), io.SeekEnd); err != nil {
			t.Logf("seek failed evidence process log: %v", err)
			return
		}
	}
	data, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		t.Logf("read failed evidence process log: %v", err)
		return
	}
	text := strings.ReplaceAll(string(data), "ENROLL-windows-scm-fixture", "[fixture-secret-redacted]")
	t.Logf("failed evidence process log:\n%s", text)
	if output != "" {
		if err := os.WriteFile(filepath.Join(output, "failed-agent-process.log"), []byte(text), 0600); err != nil {
			t.Errorf("retain failed evidence process log: %v", err)
		}
	}
}
