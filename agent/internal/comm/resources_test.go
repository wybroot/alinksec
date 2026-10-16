package comm

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/config"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/resources"
)

func TestResourcePressureKeepsControlAndOfflineEvents(t *testing.T) {
	c := reportTestClient(t)
	c.state = &State{AgentID: "resource-test"}
	c.cfg = &config.Config{HeartbeatInterval: 10 * time.Millisecond, DrainRatePerSec: 1000}
	c.resources = resources.New(resources.Config{})
	ctx, cancel := context.WithCancel(context.Background())
	reads := 0
	trims := 0
	c.monitorResources(ctx, time.Millisecond, func(context.Context) (resources.Sample, error) {
		reads++
		if reads == 3 {
			cancel()
		}
		if reads == 2 {
			return resources.Sample{At: time.Now()}, errors.New("sampler unavailable")
		}
		return resources.Sample{At: time.Now(), CPUSeconds: 1, RSSBytes: 120 << 20}, nil
	}, func() { trims++ })
	if trims != 1 || c.resources.State().Factor != 8 {
		t.Fatal("missing pressure and bounded reclamation")
	}
	reports, err := c.queue.PopAll()
	if err != nil || len(reports) != 3 {
		t.Fatalf("resource events not durable: %d %v", len(reports), err)
	}
	for _, r := range reports {
		if r.GetSecurityEvent().GetRuleId() != "agent-resources" {
			t.Fatal("wrong event")
		}
	}
	if !c.beginBulk() {
		t.Fatal("bulk slot")
	}
	for _, acks := range [][]*pb.RptAck{
		c.executeCommand(&pb.Command{CmdId: "collect", Payload: &pb.Command_CollectNow{CollectNow: &pb.CmdCollectNow{}}}, make(chan *pb.Report), context.Background()),
		c.executeBaselineCheck(&pb.CmdBaselineCheck{}, &pb.RptAck{CmdId: "baseline"}),
		c.executeVulnScan(&pb.CmdVulnScan{}, &pb.RptAck{CmdId: "vuln"}),
		c.executeVirusScan(&pb.CmdVirusScan{}, &pb.RptAck{CmdId: "virus"}),
	} {
		if len(acks) != 2 || acks[1].Stage != pb.RptAck_FAILED || acks[1].Code != 2 {
			t.Fatal("overlapping bulk work accepted")
		}
	}
	// sendLoop has its own clock and does not acquire the occupied bulk slot.
	c.cfg.DrainRatePerSec = 1
	for _, id := range []string{"backlog-a", "backlog-b", "backlog-c"} {
		if err := c.queue.Push(securityReport(id)); err != nil {
			t.Fatal(err)
		}
	}
	stream := &upgradeStream{}
	sctx, stop := context.WithTimeout(context.Background(), 160*time.Millisecond)
	defer stop()
	_ = c.sendLoop(sctx, stream, make(chan *pb.Report), 0)
	heartbeats := 0
	for _, r := range stream.reports {
		if r.GetHeartbeat() != nil {
			heartbeats++
		}
	}
	if heartbeats < 2 {
		t.Fatal("resource pressure stopped heartbeat")
	}
	if remaining, err := c.queue.PopAll(); err != nil || len(remaining) != 2 {
		t.Fatalf("backlog was lost or drained without yielding: %d %v", len(remaining), err)
	}
	c.collectPaused.Store(true)
	if c.buildHeartbeat().GetHeartbeat() == nil {
		t.Fatal("pause stopped control")
	}
}

func TestQueueCompactionContentionDoesNotBlockHeartbeat(t *testing.T) {
	c := reportTestClient(t)
	c.state = &State{AgentID: "resource-test"}
	c.cfg = &config.Config{HeartbeatInterval: 10 * time.Millisecond, DrainRatePerSec: 1}
	stream := &upgradeStream{}
	c.queue.mu.Lock()
	defer c.queue.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 130*time.Millisecond)
	defer cancel()
	_ = c.sendLoop(ctx, stream, make(chan *pb.Report), 0)
	n := 0
	for _, r := range stream.reports {
		if r.GetHeartbeat() != nil {
			n++
		}
	}
	if n < 2 {
		t.Fatal("queue compaction mutex blocked heartbeat")
	}
}

func TestResourceMetricsDoNotPublishUnknownCPUAsZero(t *testing.T) {
	for _, s := range []resources.State{{Factor: 2}, {Factor: 1, SamplingOK: true}} {
		for _, m := range resourceMetrics(s) {
			if m.Name == "alinksec_agent_cpu_percent_single_core" {
				t.Fatal("unprimed CPU looked measured")
			}
		}
	}
}

func TestReplayCachesPruneExpiredIdentities(t *testing.T) {
	c := upgradeResultClient(t, true)
	seen := map[string]string{"expired": "old"}
	if err := c.sendUpgradeResults(&upgradeStream{}, 0, seen); err != nil || len(seen) != 1 || seen["expired"] != "" {
		t.Fatalf("upgrade identity retention: %v %v", seen, err)
	}
	seen = map[string]string{"expired": "old"}
	if err := c.sendIsolationResults(&upgradeStream{}, 0, seen); err != nil || len(seen) != 0 {
		t.Fatalf("isolation identity retention: %v %v", seen, err)
	}
}
