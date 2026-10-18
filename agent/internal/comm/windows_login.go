package comm

import (
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"time"
)

func (c *Client) windowsLoginStatus() string {
	if c.windowsLogin == nil {
		return ""
	}
	return c.windowsLogin.StatusJSON()
}
func (c *Client) sendWindowsLoginEvents(stream pb.AgentChannel_ChannelClient, generation uint64, sent map[string]time.Time) error {
	if c.windowsLogin == nil {
		return nil
	}
	events := c.windowsLogin.Events()
	active := map[string]bool{}
	for _, v := range events {
		active[v.ID] = true
	}
	for k := range sent {
		if !active[k] {
			delete(sent, k)
		}
	}
	for _, v := range events {
		// Retry a committed server receipt lost on an otherwise live stream too.
		if last := sent[v.ID]; !last.IsZero() && time.Since(last) < 30*time.Second {
			continue
		}
		event := &pb.RptSecurityEvent{RuleId: v.RuleID, RuleName: v.RuleName, Type: v.Type, Severity: pb.Severity(v.Severity), Detail: v.Detail, ActionTaken: v.Action, EventTs: v.Time}
		report := &pb.Report{AgentId: c.state.AgentID, ReportId: v.ID + "-windows-login", Ts: v.Time, Payload: &pb.Report_SecurityEvent{SecurityEvent: event}}
		if err := c.sendReport(stream, report, generation); err != nil {
			return err
		}
		sent[v.ID] = time.Now()
	}
	return nil
}
