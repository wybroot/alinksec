package comm

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/isolation"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/securestate"
)

func isolationClient(t *testing.T) (*Client, *isolation.Lease) {
	t.Helper()
	work := t.TempDir()
	dir := filepath.Join(work, "isolation", "leases")
	if err := securestate.PrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	backends := []string{"/usr/sbin/iptables", "/usr/sbin/ip6tables"}
	if runtime.GOOS == "windows" {
		backends = []string{"wfp-dynamic-v1"}
	}
	l := &isolation.Lease{ID: strings.Repeat("a", 32), Generation: 1, Revision: 1, CommandID: "isolate-command", Phase: "active", Created: now, Updated: now, Deadline: now.Add(5 * time.Second), IPs: []string{"192.0.2.10"}, Port: 19443, Backends: backends}
	for path, value := range map[string]any{filepath.Join(dir, l.ID+".json"): l, filepath.Join(work, "isolation", "current.json"): l.ID} {
		if err := securestate.WriteJSON(path, value); err != nil {
			t.Fatal(err)
		}
	}
	c := &Client{workDir: work, state: &State{AgentID: "agent"}, isolationContract: 1, dedup: newCmdDedup(1000), log: slog.New(slog.NewTextHandler(io.Discard, nil)), channelActive: true, channelSession: 7}
	return c, l
}
func TestIsolationNeedsFreshOneUseConfirmationFromCurrentStream(t *testing.T) {
	c, l := isolationClient(t)
	s := &upgradeStream{}
	seen := ""
	if err := c.sendIsolationState(s, 7, &seen); err != nil {
		t.Fatal(err)
	}
	pulse := s.reports[0].GetIsolationState()
	if pulse.GetNonce() == "" || pulse.GetConfirmed() || !isTransient(s.reports[0]) {
		t.Fatal("local apply was success or pulse could enter offline replay")
	}
	echo := &pb.CmdIsolationConfirm{LeaseId: l.ID, Nonce: pulse.Nonce}
	for _, session := range []uint64{0, 6, 8} {
		c.confirmIsolation(echo, session)
	}
	wrong := &pb.CmdIsolationConfirm{LeaseId: echo.LeaseId, Nonce: strings.Repeat("b", 32)}
	c.confirmIsolation(wrong, 7)
	current, err := isolation.Current(c.workDir)
	if err != nil {
		t.Fatal(err)
	}
	if !current.Confirmed.IsZero() {
		t.Fatal("stale stream or forged nonce renewed isolation")
	}
	c.confirmIsolation(echo, 7)
	confirmed, err := isolation.Current(c.workDir)
	if err != nil || confirmed.Confirmed.IsZero() {
		t.Fatalf("valid management round trip rejected: %+v %v", confirmed, err)
	}
	c.confirmIsolation(echo, 7)
	after, _ := isolation.Current(c.workDir)
	if after.Revision != confirmed.Revision || !after.Deadline.Equal(confirmed.Deadline) {
		t.Fatal("duplicate confirmation extended lease")
	}
}
func TestExpiredNonceAndDisconnectedStreamDoNotRenew(t *testing.T) {
	for _, mode := range []string{"late", "disconnected", "replacement"} {
		t.Run(mode, func(t *testing.T) {
			c, l := isolationClient(t)
			s := &upgradeStream{}
			seen := ""
			if err := c.sendIsolationState(s, 7, &seen); err != nil {
				t.Fatal(err)
			}
			echo := &pb.CmdIsolationConfirm{LeaseId: l.ID, Nonce: s.reports[0].GetIsolationState().Nonce}
			switch mode {
			case "late":
				c.isolationChallenge.sent = time.Now().Add(-4 * time.Second)
			case "disconnected":
				c.channelActive = false
			case "replacement":
				c.channelSession = 8
			}
			c.confirmIsolation(echo, 7)
			current, _ := isolation.Current(c.workDir)
			if !current.Confirmed.IsZero() || !current.Deadline.Equal(l.Deadline) {
				t.Fatal("invalid echo extended isolation")
			}
		})
	}
}
func TestAutomaticWithdrawalReplaysHistoryWithoutReplayingCurrentState(t *testing.T) {
	c, l := isolationClient(t)
	l.Confirmed = time.Now()
	l.Phase = "finished"
	l.Restored = time.Now()
	l.Automatic = true
	l.Message = "isolation automatically withdrawn: lease_expired"
	path := filepath.Join(c.workDir, "isolation", "leases", l.ID+".json")
	if err := securestate.WriteJSON(path, l); err != nil {
		t.Fatal(err)
	}
	s := &upgradeStream{failAt: 2}
	seen := map[string]string{}
	if err := c.sendIsolationResults(s, 7, seen); err == nil {
		t.Fatal("missing partial-send failure")
	}
	s.failAt = 0
	if err := c.sendIsolationResults(s, 7, seen); err != nil {
		t.Fatal(err)
	}
	if len(s.reports) != 2 || s.reports[0].GetAck().GetStage() != pb.RptAck_DONE || s.reports[1].GetSecurityEvent().GetActionTaken() != "restored" {
		t.Fatal("automatic withdrawal corrupted command history or restoration event")
	}
	for _, r := range s.reports {
		if r.GetIsolationState() != nil {
			t.Fatal("historical replay carried current state")
		}
	}
	if err := c.sendIsolationResults(s, 8, map[string]string{}); err != nil || len(s.reports) != 4 || s.reports[1].ReportId != s.reports[3].ReportId {
		t.Fatal("reconnect did not preserve event identity")
	}
	command := &pb.Command{CmdId: l.CommandID, Payload: &pb.Command_ProtectAction{ProtectAction: &pb.CmdProtectAction{Action: pb.CmdProtectAction_ISOLATE_HOST, IsolationContract: 1}}}
	acks := c.handleCommand(command, nil, context.Background())
	if len(acks) != 1 || acks[0].Stage != pb.RptAck_DONE {
		t.Fatal("completed command was executed again")
	}
}
func TestIsolationRefusesLegacyOrNonNativeExecution(t *testing.T) {
	for _, contracts := range [][2]uint32{{0, 1}, {1, 0}, {1, 2}} {
		c := &Client{workDir: t.TempDir(), isolationContract: contracts[0], dedup: newCmdDedup(10)}
		cmd := &pb.Command{CmdId: "unsupported", Payload: &pb.Command_ProtectAction{ProtectAction: &pb.CmdProtectAction{Action: pb.CmdProtectAction_ISOLATE_HOST, IsolationContract: contracts[1]}}}
		acks := c.handleCommand(cmd, nil, context.Background())
		if len(acks) != 2 || acks[1].Stage != pb.RptAck_FAILED {
			t.Fatal("unsafe isolation accepted")
		}
	}
}
