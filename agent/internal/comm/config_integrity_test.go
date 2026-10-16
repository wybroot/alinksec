package comm

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/alinksec/alinksec-agent/internal/configguard"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func TestProtectedPolicyCannotBeDisabledByEditableShadow(t *testing.T) {
	work := t.TempDir()
	path := filepath.Join(work, "agent.yml")
	if err := os.WriteFile(path, []byte("server_addr: trusted.example:9443\ndecoy:\n  enabled: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	store, cfg, err := configguard.Open(work, path)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	c, err := NewProtected(cfg, work, log, store)
	if err != nil {
		t.Fatal(err)
	}
	good := `{"decoy":{"enabled":false},"virus_realtime":{"enabled":true,"action":"quarantine"},"virus_whitelist":[]}`
	acks := c.executeCommand(&pb.Command{CmdId: "auth-policy", Payload: &pb.Command_PolicySync{PolicySync: &pb.CmdPolicySync{PolicyVersion: "trusted-v8", PolicyJson: good}}}, nil, context.Background())
	if acks[len(acks)-1].Stage != pb.RptAck_DONE {
		t.Fatal(acks)
	}
	if err := os.WriteFile(filepath.Join(work, "policy.json"), []byte(`{"virus_realtime":{"enabled":false},"virus_whitelist":[{"type":"path","value":"/"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	// This read occurs BEFORE the next periodic hash check.
	if enabled, quarantine := c.newVirusEngine().RealtimePolicy(work); !enabled || !quarantine {
		t.Fatal("shadow disabled active protection before hash check")
	}
	store.Close()
	reopened, cfg, err := configguard.Open(work, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	next, err := NewProtected(cfg, work, log, reopened)
	if err != nil {
		t.Fatal(err)
	}
	if next.state.PolicyVersion != "trusted-v8" {
		t.Fatal("restart accepted untrusted policy version")
	}
	if b, _, _ := reopened.Policy(); string(b) != good {
		t.Fatal("restart trusted changed policy")
	}
	// Invalid authenticated snapshots must not overwrite the pinned copy.
	acks = next.executeCommand(&pb.Command{CmdId: "invalid-policy", Payload: &pb.Command_PolicySync{PolicySync: &pb.CmdPolicySync{PolicyVersion: "bad-v9", PolicyJson: `{"virus_realtime":{"enabled":false,"action":"bogus"}}`}}}, nil, context.Background())
	if acks[len(acks)-1].Stage != pb.RptAck_FAILED || next.state.PolicyVersion != "trusted-v8" {
		t.Fatal("invalid sync advanced trusted policy")
	}
}

func TestConfigurationEventReplayUsesDurableStableIdentity(t *testing.T) {
	work := t.TempDir()
	path := filepath.Join(work, "agent.yml")
	if err := os.WriteFile(path, []byte("server_addr: trusted.example:9443\n"), 0600); err != nil {
		t.Fatal(err)
	}
	store, _, err := configguard.Open(work, path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := os.WriteFile(path, []byte("enroll_token: a-secret-invalid-change\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.Check(); err != nil {
		t.Fatal(err)
	}
	c := &Client{configStore: store, state: &State{AgentID: "fixture-agent"}}
	stream := &upgradeStream{}
	if err := c.sendConfigEvents(stream, 1, map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if len(stream.reports) != 1 {
		t.Fatal("missing configuration evidence")
	}
	id := stream.reports[0].ReportId
	var detail map[string]any
	if err := json.Unmarshal([]byte(stream.reports[0].GetSecurityEvent().Detail), &detail); err != nil {
		t.Fatal(err)
	}
	if id != detail["id"].(string)+"-config-event" {
		t.Fatal("report id not bound to persistent event")
	}
	if err := c.sendConfigEvents(stream, 2, map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if len(stream.reports) != 2 || stream.reports[1].ReportId != id {
		t.Fatal("reconnect changed event identity")
	}
}
