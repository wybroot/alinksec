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
			PolicyJson:    `{"decoy":{"enabled":false,"response":"alert_only","rate_threshold":7}}`,
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
	if _, err := os.Stat(filepath.Join(workDir, "policy.json")); err != nil {
		t.Fatalf("persisted policy missing: %v", err)
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
