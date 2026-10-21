package comm

import (
	"context"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"time"
)

func (c *Client) executeScapScan(ctx context.Context, command *pb.CmdScapScan, received *pb.RptAck) []*pb.RptAck {
	if !c.beginBulk() {
		return c.resourceBusy(received)
	}
	if !c.baselineBusy.CompareAndSwap(false, true) {
		c.bulkBusy.Store(false)
		return c.resourceBusy(received)
	}
	running := &pb.RptAck{CmdId: received.GetCmdId(), Stage: pb.RptAck_RUNNING, Message: "SCAP 原生核查执行中"}
	go func() {
		defer c.baselineBusy.Store(false)
		defer c.bulkBusy.Store(false)
		defer c.resources.BeginScan()()
		result := c.scap.Scan(ctx, received.GetCmdId(), command)
		ack := &pb.RptAck{CmdId: received.GetCmdId(), Stage: pb.RptAck_DONE, Message: "SCAP 原生核查执行完成，请查看各条规则结果"}
		if result.GetState() != "complete" {
			ack.Stage = pb.RptAck_FAILED
			ack.Code = 1
			ack.Message = result.GetIssue()
		}
		c.dedup.Put(received.GetCmdId(), ack)
		c.pushReport(&pb.Report{AgentId: c.state.AgentID, ReportId: newUUID(), Ts: time.Now().UnixMilli(), Payload: &pb.Report_ScapResult{ScapResult: result}})
		c.pushReport(c.wrapAck(ack))
	}()
	return []*pb.RptAck{received, running}
}
