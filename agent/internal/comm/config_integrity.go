package comm

import (
	"context"
	"encoding/json"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/virusscan"
)

func (c *Client) watchConfiguration(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		if err := c.configStore.Check(); err != nil {
			c.log.Error("configuration integrity check could not persist recovery evidence; pinned configuration retained", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (c *Client) sendConfigEvents(stream pb.AgentChannel_ChannelClient, generation uint64, sent map[string]bool) error {
	if c.configStore == nil {
		return nil
	}
	events := c.configStore.Events()
	active := make(map[string]bool, len(events))
	for _, event := range events {
		active[event.ID] = true
	}
	for key := range sent {
		if !active[key] {
			delete(sent, key)
		}
	}
	for _, event := range events {
		if sent[event.ID] {
			continue
		}
		data, _ := json.Marshal(event)
		e := &pb.RptSecurityEvent{Type: "self_defense", RuleId: "agent-config-integrity", RuleName: "Agent 配置防篡改", Severity: pb.Severity_SEV_HIGH, EventTs: event.Time, ActionTaken: event.Action, Detail: string(data)}
		r := &pb.Report{AgentId: c.state.AgentID, ReportId: event.ID + "-config-event", Ts: event.Time, Payload: &pb.Report_SecurityEvent{SecurityEvent: e}}
		if err := c.sendReport(stream, r, generation); err != nil {
			return err
		}
		sent[event.ID] = true
	}
	return nil
}

func (c *Client) newVirusEngine() *virusscan.Engine {
	var engine *virusscan.Engine
	if c.configStore != nil {
		engine = virusscan.NewEngineWithPolicyReader(c.workDir, c.log, func() ([]byte, error) { data, _, _ := c.configStore.Policy(); return data, nil })
	} else {
		engine = virusscan.NewEngine(c.workDir, c.log)
	}
	engine.SetIOBudget(c.resources.WaitIO)
	engine.SetClamAV(c.clamav)
	engine.SetYARA(c.yara)
	return engine
}
