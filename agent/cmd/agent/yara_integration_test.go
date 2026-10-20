//go:build linux || windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/alinksec/alinksec-agent/internal/config"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/yara/yaratest"
	"gopkg.in/yaml.v3"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestNativeYARAAgent(t *testing.T) {
	if os.Getenv("ALINKSEC_YARA_AGENT_BIN") == "" {
		t.Skip("requires actual native YARA Agent binary")
	}
	cfgYara, version := yaratest.Native(t)
	cfgYara.Realtime = false
	binary := os.Getenv("ALINKSEC_YARA_AGENT_BIN")
	if !filepath.IsAbs(binary) {
		t.Fatal("absolute binary required")
	}
	root := t.TempDir()
	fixture, address, ca := newSCMFixture(t, root)
	work := filepath.Join(root, "Agent Work With Spaces")
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
	cfg.YARA = cfgYara
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	applyNativeConfig(t, binary, work, data)
	process := &configProcess{binary: binary, work: work}
	process.start(t)
	defer process.stop(t)
	connection := fixture.nextConnection(t)
	hb := fixture.awaitReport(t, connection.number, func(r *pb.Report) bool {
		h := r.GetHeartbeat()
		if h == nil || h.GetYaraContract() != 1 {
			return false
		}
		var s map[string]any
		return json.Unmarshal([]byte(h.GetYaraStatus()), &s) == nil && s["state"] == "ready" && s["version"] == version
	}).GetHeartbeat()
	fixture.awaitReport(t, connection.number, func(r *pb.Report) bool { return r.GetAsset() != nil })
	path := filepath.Join(root, "native marker.txt")
	if err := os.WriteFile(path, []byte(yaratest.Marker), 0600); err != nil {
		t.Fatal(err)
	}
	send := func(id string) {
		connection.commands <- &pb.Command{CmdId: id, IssuedAt: time.Now().UnixMilli(), Payload: &pb.Command_VirusScan{VirusScan: &pb.CmdVirusScan{TaskId: id, Mode: pb.CmdVirusScan_CUSTOM, Paths: []string{path}, Engine: "yara", ExecutionContract: 4, ExpectedDbVersion: version}}}
	}
	send("yara-actual-scan")
	report := fixture.awaitReport(t, connection.number, func(r *pb.Report) bool { return r.GetVirusResult().GetTaskId() == "yara-actual-scan" }).GetVirusResult()
	if report.Status != pb.RptVirusResult_COMPLETE || len(report.Findings) != 1 || len(report.Findings[0].MatchedRules) != 2 || report.Findings[0].EngineVersion != version || report.Findings[0].ActionTaken != "quarantined" {
		t.Fatal(report)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("actual source not quarantined", err)
	}
	found := report.Findings[0]
	connection.commands <- &pb.Command{CmdId: "yara-actual-restore", IssuedAt: time.Now().UnixMilli(), Payload: &pb.Command_VirusAction{VirusAction: &pb.CmdVirusAction{ExecutionContract: 2, Action: pb.CmdVirusAction_RESTORE, Targets: []*pb.VirusTarget{{Path: path, Sha256: found.Sha256, QuarantineId: found.QuarantineId, FindingId: "1"}}}}}
	ack := fixture.awaitReport(t, connection.number, func(r *pb.Report) bool {
		return r.GetAck().GetCmdId() == "yara-actual-restore" && (r.GetAck().GetStage() == pb.RptAck_DONE || r.GetAck().GetStage() == pb.RptAck_FAILED)
	}).GetAck()
	restored, restoreErr := os.ReadFile(path)
	if ack.Stage != pb.RptAck_DONE || restoreErr != nil || !bytes.Equal(restored, []byte(yaratest.Marker)) {
		t.Fatalf("restore=%v err=%v bytes=%q", ack, restoreErr, restored)
	}
	// A changed pinned source must fail through the real command and mTLS report path.
	os.WriteFile(path, []byte(yaratest.Marker), 0600)
	os.WriteFile(cfgYara.RulesFile, []byte("rule Changed {condition:true}"), 0600)
	send("yara-actual-changed-source")
	failed := fixture.awaitReport(t, connection.number, func(r *pb.Report) bool { return r.GetVirusResult().GetTaskId() == "yara-actual-changed-source" }).GetVirusResult()
	if failed.Status != pb.RptVirusResult_FAILED || len(failed.Findings) != 0 {
		t.Fatal(failed)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("failure removed actual file", err)
	}
	if dest := os.Getenv("ALINKSEC_YARA_AGENT_EVIDENCE_FILE"); dest != "" {
		b, _ := json.MarshalIndent(map[string]any{"passed": true, "os": runtime.GOOS, "arch": runtime.GOARCH, "version": version, "checks": []string{"actual-native-agent-enrollment-mtls", "approved-local-yara-config", "heartbeat-native-contract-and-version", "real-command-native-scan-quarantine-and-matched-rules", "changed-source-fails-without-quarantine", "real-command-digest-bound-restore"}, "heartbeat": hb.GetYaraStatus(), "finding": report.Findings[0]}, "", "  ")
		if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dest, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
