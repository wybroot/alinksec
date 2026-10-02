package comm

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/alinksec/alinksec-agent/internal/config"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func TestPolicySyncAppliesAndPersistsSnapshotBeforeVersion(t *testing.T) {
	workDir := t.TempDir()
	cfg := &config.Config{}
	cfg.Decoy.Normalize()
	client, err := New(cfg, workDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	acks := client.executeCommand(&pb.Command{
		CmdId: "policy-success",
		Payload: &pb.Command_PolicySync{PolicySync: &pb.CmdPolicySync{
			PolicyVersion: "v42",
			PolicyJson:    `{"decoy":{"enabled":false,"response":"alert_only","rate_threshold":7},"process_rules":[{"id":"PR-0001","name":"miner","enabled":true,"severity":4,"match":{"exe_regex":"xmrig"},"actions":["kill","alert"]}],"file_rules":[{"id":"PR-0002","enabled":true,"match":{"platforms":["linux"],"paths":["/work/protected"]},"actions":["alert"]}],"login_rules":[{"id":"PR-0003","enabled":true,"match":{"failure_threshold":3,"timezone":"UTC"},"actions":["alert"]}]}`,
		}},
	}, nil, context.Background())

	if len(acks) != 2 || acks[1].GetStage() != pb.RptAck_DONE {
		t.Fatalf("acks = %#v, want RECEIVED then DONE", acks)
	}
	if client.state.PolicyVersion != "v42" {
		t.Fatalf("policy version = %q, want v42", client.state.PolicyVersion)
	}
	if client.cfg.Decoy.Enabled == nil || *client.cfg.Decoy.Enabled {
		t.Fatalf("decoy enabled = %v, want false", client.cfg.Decoy.Enabled)
	}
	if client.cfg.Decoy.Response != "alert_only" || client.cfg.Decoy.RateThreshold != 7 {
		t.Fatalf("decoy config = %#v, want synced values", client.cfg.Decoy)
	}
	if len(client.cfg.ProcessRules) != 1 || client.cfg.ProcessRules[0].ID != "PR-0001" {
		t.Fatalf("process rules = %#v, want synced EDR rule", client.cfg.ProcessRules)
	}
	if _, err := os.Stat(filepath.Join(workDir, "policy.json")); err != nil {
		t.Fatalf("persisted policy missing: %v", err)
	}
	reloaded, err := New(&config.Config{}, workDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil || len(reloaded.cfg.FileRules) != 1 || len(reloaded.cfg.LoginRules) != 1 || reloaded.cfg.LoginRules[0].Match.FailureThreshold != 3 {
		t.Fatalf("persisted protection policy did not reload: %v", err)
	}
}

func TestInvalidProtectionSnapshotPreservesLastGoodPolicyAndVersion(t *testing.T) {
	workDir := t.TempDir()
	client, err := New(&config.Config{}, workDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	good := `{"login_rules":[{"id":"login","enabled":true,"match":{"failure_threshold":5},"actions":["alert"]}]}`
	if err := client.applyPolicyJson(good, true); err != nil {
		t.Fatal(err)
	}
	client.state.PolicyVersion = "v1"
	for _, bad := range []string{`{"login_rules":[{"id":"login","match":{"failure_threshold":1}}]}`, `{"file_rules":[{"id":"file","match":{"paths":["relative"]}}]}`} {
		acks := client.executeCommand(&pb.Command{CmdId: "bad-protection", Payload: &pb.Command_PolicySync{PolicySync: &pb.CmdPolicySync{PolicyVersion: "v2", PolicyJson: bad}}}, nil, context.Background())
		if acks[len(acks)-1].GetStage() != pb.RptAck_FAILED || client.state.PolicyVersion != "v1" {
			t.Fatal("invalid policy advanced version")
		}
		stored, err := os.ReadFile(filepath.Join(workDir, "policy.json"))
		if err != nil || string(stored) != good || client.cfg.LoginRules[0].Match.FailureThreshold != 5 {
			t.Fatal("invalid policy replaced last good state")
		}
	}
}

func TestPolicySyncRejectsInvalidSnapshotWithoutAdvancingVersion(t *testing.T) {
	workDir := t.TempDir()
	cfg := &config.Config{}
	cfg.Decoy.Normalize()
	client, err := New(cfg, workDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	client.state.PolicyVersion = "v41"

	acks := client.executeCommand(&pb.Command{
		CmdId: "policy-invalid",
		Payload: &pb.Command_PolicySync{PolicySync: &pb.CmdPolicySync{
			PolicyVersion: "v42",
			PolicyJson:    `{not-json`,
		}},
	}, nil, context.Background())

	if len(acks) != 2 || acks[1].GetStage() != pb.RptAck_FAILED {
		t.Fatalf("acks = %#v, want RECEIVED then FAILED", acks)
	}
	if client.state.PolicyVersion != "v41" {
		t.Fatalf("policy version = %q, want v41", client.state.PolicyVersion)
	}
	if _, err := os.Stat(filepath.Join(workDir, "policy.json")); !os.IsNotExist(err) {
		t.Fatalf("invalid policy should not persist, stat error = %v", err)
	}
}
