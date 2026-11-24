package comm

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/config"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/virusscan"
)

func TestVirusActionStructuredErrorReceiptOnFailure(t *testing.T) {
	client := reportTestClient(t)
	client.workDir = t.TempDir()
	client.state = &State{AgentID: "fixture-agent"}
	client.dedup = newCmdDedup(100)
	client.setChannelActive(true)

	path := filepath.Join(t.TempDir(), "changed.sh")
	if err := os.WriteFile(path, []byte("current-bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("expected-different-bytes"))
	wrongHash := hex.EncodeToString(sum[:])

	cmd := &pb.CmdVirusAction{
		ExecutionContract: 2,
		Action:            pb.CmdVirusAction_QUARANTINE,
		Targets: []*pb.VirusTarget{
			{FindingId: "1", Path: path, Sha256: wrongHash},
		},
	}
	acks := client.executeVirusAction(cmd, &pb.RptAck{CmdId: "bkl016-err-code"}, time.Now().UnixMilli())
	if len(acks) != 2 || acks[1].Stage != pb.RptAck_RUNNING {
		t.Fatalf("unexpected acks: %+v", acks)
	}
	var report *pb.Report
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		report, err = client.queue.Peek()
		if err != nil {
			t.Fatal(err)
		}
		if report != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if report == nil || report.GetAck() == nil {
		t.Fatal("missing terminal action receipt")
	}
	ack := report.GetAck()
	if ack.Stage != pb.RptAck_FAILED || ack.Code != 1 {
		t.Fatalf("expected FAILED code=1, got %+v", ack)
	}
	var receipt struct {
		Contract int `json:"virus_action_contract"`
		Results  []struct {
			FindingID string `json:"finding_id"`
			Success   bool   `json:"success"`
			Error     string `json:"error"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(ack.Message), &receipt); err != nil || receipt.Contract != 2 || len(receipt.Results) != 1 {
		t.Fatalf("invalid receipt JSON: %s err=%v", ack.Message, err)
	}
	if receipt.Results[0].Success || receipt.Results[0].Error == "" || len(receipt.Results[0].Error) > 128 {
		t.Fatalf("unexpected result error field: %+v", receipt.Results[0])
	}
	if code := virusscan.ActionErrorCode(nil); code != "" {
		t.Fatalf("expected empty code on nil, got %q", code)
	}
}

func TestStartupQuarantineReconcileAndDiagnosticSummary(t *testing.T) {
	workDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{ServerAddr: "127.0.0.1:0"}
	client, err := NewProtected(cfg, workDir, logger, nil)
	if err != nil {
		t.Fatalf("NewProtected failed on fresh workDir: %v", err)
	}
	client.quarantineReconcile = virusscan.ReconcileReport{
		ScannedObjects:      4,
		ActiveObjects:       2,
		PromotedActive:      1,
		RolledBackPrepared:  1,
		CompletedDeletes:    1,
		CleanedOrphanTemp:   3,
		CleanedTerminalBody: 1,
		CleanedStageDirs:    1,
	}
	zipBytes, err := client.diagnosticZIP("req-bkl016")
	if err != nil {
		t.Fatalf("diagnosticZIP failed: %v", err)
	}
	if strings.Contains(string(zipBytes), workDir) {
		t.Fatal("diagnostic bundle leaked host workDir")
	}
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range zr.File {
		if f.Name != "runtime.json" {
			continue
		}
		found = true
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]any
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatal(err)
		}
		rec, ok := payload["quarantineReconcile"].(map[string]any)
		if !ok {
			t.Fatalf("missing quarantineReconcile summary in runtime.json: %s", string(raw))
		}
		if rec["scanned_objects"] != float64(4) || rec["promoted_active"] != float64(1) || rec["cleaned_stage_dirs"] != float64(1) {
			t.Fatalf("unexpected quarantineReconcile counters: %+v", rec)
		}
	}
	if !found {
		t.Fatal("runtime.json not found in diagnostic zip")
	}
}
