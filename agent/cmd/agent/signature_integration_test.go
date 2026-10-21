//go:build linux || windows

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/config"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"
)

func TestNativeSignatureAgent(t *testing.T) {
	binary, dir := os.Getenv("ALINKSEC_SIGNATURE_AGENT_BIN"), os.Getenv("ALINKSEC_SIGNATURE_FIXTURE_DIR")
	if binary == "" || dir == "" {
		t.Skip("requires an actual Agent and independent release fixtures")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("absolute Agent binary required")
	}
	read := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	var release map[string]json.RawMessage
	if err := json.Unmarshal(read("release.json"), &release); err != nil {
		t.Fatal(err)
	}
	value := func(key string) string {
		var s string
		if err := json.Unmarshal(release[key], &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	root := t.TempDir()
	fixture, address, ca := newSCMFixture(t, root)
	for _, name := range []string{"base.zip", "target.zip", "delta.zip"} {
		fixture.packages.Store("/"+name, read(name))
	}
	work := filepath.Join(root, "Signature Agent Work With Spaces")
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
	process := &configProcess{binary: binary, work: work}
	process.start(t)
	defer process.stop(t)
	connection := fixture.nextConnection(t)
	fixture.awaitReport(t, connection.number, func(r *pb.Report) bool { return r.GetHeartbeat().GetSignatureUpdateContract() == 1 })
	fixture.awaitReport(t, connection.number, func(r *pb.Report) bool { return r.GetAsset() != nil })
	send := func(id string, update *pb.CmdSignatureUpdate) *pb.RptAck {
		connection.commands <- &pb.Command{CmdId: id, IssuedAt: time.Now().UnixMilli(), Payload: &pb.Command_SignatureUpdate{SignatureUpdate: update}}
		return fixture.awaitReport(t, connection.number, func(r *pb.Report) bool {
			return r.GetAck().GetCmdId() == id && (r.GetAck().GetStage() == pb.RptAck_DONE || r.GetAck().GetStage() == pb.RptAck_FAILED)
		}).GetAck()
	}
	ack := send("signature-base", &pb.CmdSignatureUpdate{DbVersion: value("base_version"), DownloadUrl: fixture.downloadURL + "/base.zip", Sha256: value("base_sha256")})
	if ack.Stage != pb.RptAck_DONE {
		t.Fatal("legacy full update failed", ack)
	}
	update := &pb.CmdSignatureUpdate{DbVersion: value("version"), DownloadUrl: fixture.downloadURL + "/target.zip", Sha256: value("sha256"), UpdateContract: 1, DeltaUrl: fixture.downloadURL + "/delta.zip", DeltaSha256: value("delta_sha256"), BaseVersion: value("base_version"), BaseContentSha256: value("base_content_sha256"), ContentSha256: value("content_sha256")}
	ack = send("signature-delta", update)
	var receipt map[string]any
	if ack.Stage != pb.RptAck_DONE || json.Unmarshal([]byte(ack.Message), &receipt) != nil || receipt["mode"] != "delta" || receipt["content_sha256"] != value("content_sha256") {
		t.Fatal("actual delta command failed", ack)
	}
	replay := send("signature-repeat", update)
	var repeated map[string]any
	if replay.Stage != pb.RptAck_DONE || json.Unmarshal([]byte(replay.Message), &repeated) != nil || repeated["mode"] != "already-current" {
		t.Fatal("actual replay not idempotent", replay)
	}
	bad := proto.Clone(update).(*pb.CmdSignatureUpdate)
	bad.ContentSha256 = strings.Repeat("0", 64)
	failed := send("signature-invalid-target", bad)
	if failed.Stage != pb.RptAck_FAILED {
		t.Fatal("invalid target acknowledged complete", failed)
	}
	path := filepath.Join(root, "new-hash-marker.txt")
	if err := os.WriteFile(path, []byte("new-harmless-entry"), 0600); err != nil {
		t.Fatal(err)
	}
	connection.commands <- &pb.Command{CmdId: "signature-scan", Payload: &pb.Command_VirusScan{VirusScan: &pb.CmdVirusScan{TaskId: "signature-scan", Mode: pb.CmdVirusScan_CUSTOM, Paths: []string{path}, ExecutionContract: 2, ExpectedDbVersion: value("version")}}}
	scan := fixture.awaitReport(t, connection.number, func(r *pb.Report) bool { return r.GetVirusResult().GetTaskId() == "signature-scan" }).GetVirusResult()
	if scan.Status != pb.RptVirusResult_COMPLETE || scan.DbVersion != value("version") || len(scan.Findings) != 1 || scan.Findings[0].Name != "Added.Fixture" || scan.Findings[0].ActionTaken != "quarantined" {
		t.Fatal("actual scan did not use verified delta", scan)
	}
	process.stop(t)
	process.start(t)
	connection = fixture.nextConnection(t)
	fixture.awaitReport(t, connection.number, func(r *pb.Report) bool {
		return r.GetHeartbeat().GetSignatureUpdateContract() == 1 && r.GetHeartbeat().GetDbVersion() == value("version")
	})
	if dest := os.Getenv("ALINKSEC_SIGNATURE_AGENT_EVIDENCE_FILE"); dest != "" {
		evidence, _ := json.MarshalIndent(map[string]any{"passed": true, "os": runtime.GOOS, "arch": runtime.GOARCH, "version": value("version"), "content_sha256": value("content_sha256"), "receipt": receipt, "replay": repeated, "finding": scan.Findings[0], "checks": []string{"actual-agent-enrollment-and-mtls", "heartbeat-update-contract", "legacy-full-command", "actual-delta-command-and-content-receipt", "actual-idempotent-replay", "invalid-target-fails-with-old-library-preserved", "actual-updated-hash-scan-and-quarantine", "restart-persists-verified-version"}}, "", "  ")
		if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dest, evidence, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
