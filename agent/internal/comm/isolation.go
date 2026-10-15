package comm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"time"

	"github.com/alinksec/alinksec-agent/internal/isolation"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

// A nonce belongs to one authenticated stream, one lease and a short send
// window. It is consumed before disk I/O; repeated echoes cannot extend leases.
type isolationChallenge struct {
	session      uint64
	lease, nonce string
	sent         time.Time
}

func (c *Client) confirmIsolation(echo *pb.CmdIsolationConfirm, session uint64) {
	c.reportMu.Lock()
	active := c.channelActive && c.channelSession == session
	defer c.reportMu.Unlock()
	if !active {
		return
	}
	c.isolationMu.Lock()
	pending := c.isolationChallenge
	now := time.Now()
	valid := pending.session == session && pending.lease == echo.GetLeaseId() && pending.nonce != "" && pending.nonce == echo.GetNonce() && !now.Before(pending.sent) && now.Sub(pending.sent) <= 3*time.Second
	if valid {
		c.isolationChallenge = isolationChallenge{}
	}
	c.isolationMu.Unlock()
	if valid {
		if err := isolation.Confirm(c.workDir, pending.lease, now); err != nil {
			c.log.Warn("isolation confirmation refused", "err", err)
		}
	}
}
func (c *Client) sendIsolationState(stream pb.AgentChannel_ChannelClient, session uint64, seen *string) error {
	if c.isolationContract != 1 {
		return nil
	}
	l, err := isolation.Current(c.workDir)
	state := &pb.RptIsolationState{Phase: "normal"}
	if err != nil && !os.IsNotExist(err) {
		state.Phase = "unknown"
		state.Message = "local isolation journal unreadable"
	}
	if err == nil {
		state = &pb.RptIsolationState{LeaseId: l.ID, Generation: l.Generation, Revision: l.Revision, CommandId: l.CommandID, RestoreCommandId: l.RestoreCommandID, Phase: l.Phase, Confirmed: !l.Confirmed.IsZero(), Automatic: l.Automatic, Message: l.Message, Deadline: l.Deadline.UnixMilli()}
	}
	data, _ := json.Marshal(state)
	key := string(data)
	if key == *seen && state.Phase != "active" {
		return nil
	}
	if state.Phase == "active" {
		nonce, err := isolation.NewNonce()
		if err != nil {
			return err
		}
		state.Nonce = nonce
		c.isolationMu.Lock()
		c.isolationChallenge = isolationChallenge{session: session, lease: state.LeaseId, nonce: nonce, sent: time.Now()}
		c.isolationMu.Unlock()
	}
	// This snapshot and nonce are transient, even when Send fails. Old local
	// state must never be replayed over a newer lease after reconnection.
	err = c.sendReport(stream, &pb.Report{AgentId: c.state.AgentID, ReportId: newUUID(), Ts: time.Now().UnixMilli(), Payload: &pb.Report_IsolationState{IsolationState: state}}, session)
	if err == nil {
		*seen = key
	}
	return err
}
func isolationAck(l isolation.Lease, command string) *pb.RptAck {
	ack := &pb.RptAck{CmdId: command, Stage: pb.RptAck_RECEIVED, Message: l.Message}
	if command == l.CommandID {
		if !l.Confirmed.IsZero() {
			ack.Stage = pb.RptAck_DONE
			ack.Message = "host isolation confirmed by authenticated management round trip"
		} else if l.Phase == "finished" || l.Phase == "attention" {
			ack.Stage = pb.RptAck_FAILED
			ack.Code = 1
		}
	} else if command == l.RestoreCommandID && l.Phase == "finished" {
		ack.Stage = pb.RptAck_DONE
	}
	return ack
}
func (c *Client) sendIsolationResults(stream pb.AgentChannel_ChannelClient, session uint64, seen map[string]string) error {
	leases, err := isolation.Outcomes(c.workDir)
	if err != nil {
		c.log.Error("read persistent isolation outcomes", "err", err)
		return nil
	}
	for _, l := range leases {
		for _, cmd := range []string{l.CommandID, l.RestoreCommandID} {
			if cmd == "" || len(cmd) > 6 && cmd[:6] == "local-" {
				continue
			}
			ack := isolationAck(l, cmd)
			if !terminal(ack) {
				continue
			}
			data, _ := json.Marshal(ack)
			sum := sha256.Sum256(data)
			key := hex.EncodeToString(sum[:16])
			if seen[cmd] == key {
				continue
			}
			r := c.wrapAck(ack)
			r.ReportId = key + "-isolation-ack"
			if err := c.sendReport(stream, r, session); err != nil {
				return err
			}
			c.dedup.Put(cmd, ack)
			seen[cmd] = key
		}
		if l.Phase != "finished" && l.Phase != "attention" {
			continue
		}
		// Changes to a lease's renewal revision are not security events. Emit a
		// bounded, stable outcome event on automatic withdrawal or cleanup error.
		if !l.Automatic && l.Phase != "attention" {
			continue
		}
		eventKey := l.ID + "-" + l.Phase
		if seen[eventKey] != "" {
			continue
		}
		data, _ := json.Marshal(l)
		action := "restored"
		if l.Phase == "attention" {
			action = "alert_only"
		}
		event := &pb.RptSecurityEvent{Type: "self_defense", RuleId: "host-isolation-lease", RuleName: "主机隔离自动恢复", Severity: pb.Severity_SEV_HIGH, Detail: string(data), ActionTaken: action, EventTs: l.Updated.UnixMilli()}
		if err := c.sendReport(stream, &pb.Report{AgentId: c.state.AgentID, ReportId: eventKey + "-event", Ts: l.Updated.UnixMilli(), Payload: &pb.Report_SecurityEvent{SecurityEvent: event}}, session); err != nil {
			return err
		}
		seen[eventKey] = "sent"
	}
	return nil
}
