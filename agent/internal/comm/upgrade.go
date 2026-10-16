package comm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/upgrade"
)

func upgradeAck(result upgrade.Outcome) *pb.RptAck {
	ack := &pb.RptAck{CmdId: result.CommandID, Stage: pb.RptAck_FAILED, Code: 1, Message: result.Message}
	if result.Success {
		ack.Stage = pb.RptAck_DONE
		ack.Code = 0
	}
	return ack
}

func (c *Client) sendUpgradeResults(stream pb.AgentChannel_ChannelClient, generation uint64, seen map[string]string) error {
	results, err := upgrade.Outcomes(c.workDir)
	if err != nil {
		c.log.Error("read persistent upgrade results", "err", err)
		return nil
	}
	active := make(map[string]bool, len(results))
	for _, result := range results {
		active[result.ID] = true
	}
	for key := range seen {
		if !active[key] {
			delete(seen, key)
		}
	}
	for _, result := range results {
		data, _ := json.Marshal(result)
		digest := sha256.Sum256(data)
		key := hex.EncodeToString(digest[:16])
		if seen[result.ID] == key {
			continue
		}
		ack := upgradeAck(result)
		r := c.wrapAck(ack)
		r.ReportId = key + "-upgrade-ack"
		if err := c.sendReport(stream, r, generation); err != nil {
			return err
		}
		if !result.Success {
			action := "alert_only"
			if result.RolledBack {
				action = "restored"
			}
			event := &pb.RptSecurityEvent{Type: "self_defense", RuleId: "agent-upgrade", RuleName: "Agent upgrade startup failure", Severity: pb.Severity_SEV_HIGH, Detail: string(data), ActionTaken: action, EventTs: result.Time.UnixMilli()}
			if err := c.sendReport(stream, &pb.Report{AgentId: c.state.AgentID, ReportId: key + "-upgrade-event", Ts: result.Time.UnixMilli(), Payload: &pb.Report_SecurityEvent{SecurityEvent: event}}, generation); err != nil {
				return err
			}
		}
		c.dedup.Put(result.CommandID, ack)
		seen[result.ID] = key
	}
	return nil
}
