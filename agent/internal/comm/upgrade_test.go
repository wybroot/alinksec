package comm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/config"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/upgrade"
	"google.golang.org/grpc/metadata"
)

type upgradeStream struct {
	reports  []*pb.Report
	failAt   int
	attempts int
}

func (s *upgradeStream) Send(r *pb.Report) error {
	s.attempts++
	if s.failAt == s.attempts {
		return errors.New("connection lost")
	}
	s.reports = append(s.reports, r)
	return nil
}
func (*upgradeStream) Recv() (*pb.Command, error)   { return nil, io.EOF }
func (*upgradeStream) Header() (metadata.MD, error) { return nil, nil }
func (*upgradeStream) Trailer() metadata.MD         { return nil }
func (*upgradeStream) CloseSend() error             { return nil }
func (*upgradeStream) Context() context.Context     { return context.Background() }
func (*upgradeStream) SendMsg(any) error            { return nil }
func (*upgradeStream) RecvMsg(any) error            { return io.EOF }

func upgradeResultClient(t *testing.T, success bool) *Client {
	t.Helper()
	work := t.TempDir()
	dir := filepath.Join(work, "upgrade", "results")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	r := upgrade.Outcome{ID: strings.Repeat("b", 32), CommandID: "upgrade-command", Version: "test", Success: success, RolledBack: !success, Message: "durable result", Time: time.Now()}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, r.ID+".json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	return &Client{workDir: work, state: &State{AgentID: "agent"}, dedup: newCmdDedup(1000), log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func TestUpgradeResultReplaysAfterPartialSendAndReconnect(t *testing.T) {
	c := upgradeResultClient(t, false)
	stream := &upgradeStream{failAt: 2}
	seen := map[string]string{}
	if err := c.sendUpgradeResults(stream, 0, seen); err == nil || len(seen) != 0 {
		t.Fatal("partial send consumed durable result")
	}
	firstID := stream.reports[0].ReportId
	stream.failAt = 0
	if err := c.sendUpgradeResults(stream, 0, seen); err != nil {
		t.Fatal(err)
	}
	if len(stream.reports) != 3 || stream.reports[1].ReportId != firstID || stream.reports[1].GetAck().GetStage() != pb.RptAck_FAILED || stream.reports[2].GetSecurityEvent().GetActionTaken() != "restored" {
		t.Fatal("failure/event replay changed identity or outcome")
	}
	if err := c.sendUpgradeResults(stream, 0, seen); err != nil || len(stream.reports) != 3 {
		t.Fatal("resent result repeatedly within one connection")
	}
	if err := c.sendUpgradeResults(stream, 0, map[string]string{}); err != nil || len(stream.reports) != 5 || stream.reports[3].ReportId != firstID {
		t.Fatal("reconnect did not replay stable reports")
	}
	replayed := c.handleCommand(&pb.Command{CmdId: "upgrade-command", Payload: &pb.Command_AgentUpgrade{AgentUpgrade: &pb.CmdAgentUpgrade{}}}, nil, context.Background())
	if len(replayed) != 1 || replayed[0].GetStage() != pb.RptAck_FAILED {
		t.Fatal("completed upgrade ran again")
	}
}

func TestUpgradeSuccessIsFinalOnlyFromPersistentOutcome(t *testing.T) {
	c := upgradeResultClient(t, true)
	s := &upgradeStream{}
	if err := c.sendUpgradeResults(s, 0, map[string]string{}); err != nil || len(s.reports) != 1 || s.reports[0].GetAck().GetStage() != pb.RptAck_DONE {
		t.Fatal("confirmed success not reported")
	}
	c.dedup.Put("upgrade-command", &pb.RptAck{Stage: pb.RptAck_RECEIVED})
	if c.dedup.Get("upgrade-command").GetStage() != pb.RptAck_DONE {
		t.Fatal("asynchronous accepted ACK overwrote terminal result")
	}
}

func TestUpgradeRefusesLegacyCommandAndUnsupportedSupervisor(t *testing.T) {
	for _, contracts := range [][2]uint32{{0, 1}, {1, 0}, {1, 2}} {
		t.Run(string(rune('a'+contracts[0]*3+contracts[1])), func(t *testing.T) {
			c := &Client{workDir: t.TempDir(), dedup: newCmdDedup(1000), upgradeContract: contracts[0]}
			acks := c.handleCommand(&pb.Command{CmdId: "unsupported", Payload: &pb.Command_AgentUpgrade{AgentUpgrade: &pb.CmdAgentUpgrade{ExecutionContract: contracts[1]}}}, nil, context.Background())
			if len(acks) != 2 || acks[1].GetStage() != pb.RptAck_FAILED {
				t.Fatal("unsupported upgrade was accepted")
			}
			if _, err := os.Stat(filepath.Join(c.workDir, "upgrade")); !os.IsNotExist(err) {
				t.Fatal("unsupported upgrade changed disk state")
			}
		})
	}
}

func TestReconnectAdvertisesUpgradeCapabilityBeforeBacklog(t *testing.T) {
	for _, source := range []string{"pending", "offline"} {
		t.Run(source, func(t *testing.T) {
			c := reportTestClient(t)
			c.workDir = t.TempDir()
			c.cfg = &config.Config{HeartbeatInterval: time.Hour, DrainRatePerSec: 1}
			c.state = &State{AgentID: "agent"}
			c.upgradeContract = 1
			backlog := securityReport("backlog-before-upgrade")
			if source == "pending" {
				c.pendingReports <- backlog
			} else if err := c.queue.Push(backlog); err != nil {
				t.Fatal(err)
			}
			// Disconnect while draining, after the first report was accepted.
			stream := &upgradeStream{failAt: 2}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := c.sendLoop(ctx, stream, make(chan *pb.Report), 0); err == nil {
				t.Fatal("missing backlog transport failure")
			}
			if len(stream.reports) != 1 || stream.reports[0].GetHeartbeat().GetUpgradeContract() != 1 {
				t.Fatalf("first report did not establish upgrade capability: %v", stream.reports)
			}
			remaining, err := c.queue.PopAll()
			if err != nil || len(remaining) != 1 || remaining[0].GetReportId() != backlog.GetReportId() {
				t.Fatalf("heartbeat ordering lost failed backlog: %v, %v", remaining, err)
			}
		})
	}
}
