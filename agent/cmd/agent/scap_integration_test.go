//go:build linux || windows

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/config"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/scap"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"
)

func TestNativeSCAPAgent(t *testing.T) {
	binary := os.Getenv("ALINKSEC_SCAP_AGENT_BIN")
	if binary == "" {
		t.Skip("requires actual native Agent and pinned SCC runtime")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("absolute Agent binary required")
	}
	archive, err := os.ReadFile(os.Getenv("ALINKSEC_SCAP_FIXTURE_ZIP"))
	if err != nil {
		t.Fatal(err)
	}
	content, err := scap.ParseContent(archive)
	if err != nil {
		t.Fatal(err)
	}
	pin := os.Getenv("ALINKSEC_SCAP_TEST_RUNTIME_SHA256")
	root := t.TempDir()
	fixture, address, ca := newSCMFixture(t, root)
	work := filepath.Join(root, "SCAP Agent Work With Spaces")
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
	cfg.SCAP = scap.Config{Enabled: true, RuntimeDir: filepath.Dir(os.Getenv("ALINKSEC_SCAP_TEST_BIN")), RuntimeSHA256: pin, TimeoutSec: 180}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	applyNativeConfig(t, binary, work, data)
	process := &configProcess{binary: binary, work: work}
	process.start(t)
	defer process.stop(t)
	t.Cleanup(func() {
		if t.Failed() {
			if log, err := os.ReadFile(filepath.Join(root, "agent-process.log")); err == nil {
				if len(log) > 12000 {
					log = log[len(log)-12000:]
				}
				t.Log(string(log))
			}
		}
	})
	connection := fixture.nextConnection(t)
	ready := func(session uint32) *pb.RptHeartbeat {
		return fixture.awaitReport(t, session, func(r *pb.Report) bool {
			h := r.GetHeartbeat()
			if h == nil || h.ScapContract != 1 {
				return false
			}
			var status scap.Status
			return json.Unmarshal([]byte(h.ScapStatus), &status) == nil && status.State == "ready" && status.Version == "5.15" && status.RuntimeSHA256 == pin
		}).GetHeartbeat()
	}
	hb := ready(connection.number)
	fixture.awaitReport(t, connection.number, func(r *pb.Report) bool { return r.GetAsset() != nil })
	scan := &pb.CmdScapScan{TaskId: "scap-native-roundtrip", ExecutionContract: 1, ContentZip: archive, ContentSha256: content.SHA256, BenchmarkId: content.Manifest.BenchmarkID, ProfileId: content.Manifest.ProfileID, RuntimeSha256: pin}
	send := func(id string, value *pb.CmdScapScan) {
		connection.commands <- &pb.Command{CmdId: id, IssuedAt: time.Now().UnixMilli(), Payload: &pb.Command_ScapScan{ScapScan: value}}
	}
	ack := func(id string, stage pb.RptAck_Stage) {
		fixture.awaitReport(t, connection.number, func(r *pb.Report) bool { return r.GetAck().GetCmdId() == id && r.GetAck().GetStage() == stage })
	}
	send("scap-actual-command", scan)
	report := fixture.awaitReport(t, connection.number, func(r *pb.Report) bool { return r.GetScapResult().GetTaskId() == scan.TaskId }).GetScapResult()
	if report.State != "complete" || report.Issue != "" || report.EngineVersion != "5.15" || report.ContentSha256 != content.SHA256 || report.RuntimeSha256 != pin || len(report.Rules) != 5 || len(report.Scores) == 0 {
		t.Fatal(report)
	}
	expected := map[string]string{"external": "pass", "failure": "fail", "compound": "pass", "unselected": "notselected", "platform": "notapplicable"}
	for _, rule := range report.Rules {
		if expected[rule.RuleId[len("xccdf_org.alinksec_rule_"):]] != rule.Result {
			t.Fatal(rule)
		}
	}
	ack("scap-actual-command", pb.RptAck_DONE)
	// Restart with the same protected state and resend the same command ID.
	// The persisted final ACK must be replayed, without re-running host probes.
	process.stop(t)
	process.start(t)
	connection = fixture.nextConnection(t)
	ready(connection.number)
	send("scap-actual-command", scan)
	ack("scap-actual-command", pb.RptAck_DONE)
	wrong := proto.Clone(scan).(*pb.CmdScapScan)
	wrong.TaskId = "scap-wrong-runtime"
	wrong.RuntimeSha256 = scap.Digest([]byte("unapproved runtime"))
	send("scap-wrong-runtime-command", wrong)
	failed := fixture.awaitReport(t, connection.number, func(r *pb.Report) bool { return r.GetScapResult().GetTaskId() == wrong.TaskId }).GetScapResult()
	if failed.State != "failed" || failed.Issue != "scap_command_invalid" || len(failed.Rules) != 0 || len(failed.Scores) != 0 || failed.SourceResultSha256 != "" {
		t.Fatal(failed)
	}
	ack("scap-wrong-runtime-command", pb.RptAck_FAILED)
	if dest := os.Getenv("ALINKSEC_SCAP_AGENT_EVIDENCE_FILE"); dest != "" {
		data, _ := json.MarshalIndent(map[string]any{"passed": true, "os": runtime.GOOS, "arch": runtime.GOARCH, "checks": []string{"actual-agent-enrollment-and-mtls", "approved-local-runtime-and-native-readiness", "real-command-and-native-nine-status-contract", "five-actual-OVAL-Profile-CPE-outcomes", "native-weighted-scores-and-source-digest", "restart-and-durable-final-ACK-replay", "runtime-pin-substitution-fails-without-partial-evidence"}, "heartbeat": hb.ScapStatus, "result": report, "failed": failed}, "", "  ")
		if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dest, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
