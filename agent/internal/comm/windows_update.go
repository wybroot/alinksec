package comm

import (
	"encoding/json"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/windowsupdate"
)

func (c *Client) executeWindowsUpdateScan(scan *pb.CmdWindowsUpdateScan, received *pb.RptAck) []*pb.RptAck {
	if !c.windowsUpdateBusy.CompareAndSwap(false, true) {
		return []*pb.RptAck{received, {CmdId: received.CmdId, Stage: pb.RptAck_FAILED, Code: 2, Message: "Windows 更新发现或复核正在执行"}}
	}
	if !c.beginBulk() {
		c.windowsUpdateBusy.Store(false)
		return c.resourceBusy(received)
	}
	go func() {
		defer c.windowsUpdateBusy.Store(false)
		defer c.bulkBusy.Store(false)
		snapshot := windowsupdate.Scan(scan.DeadlineUnixMs)
		data, _ := json.Marshal(snapshot)
		c.pushReport(&pb.Report{AgentId: c.state.AgentID, ReportId: newUUID(), Ts: time.Now().UnixMilli(), Payload: &pb.Report_WindowsUpdate{WindowsUpdate: &pb.RptWindowsUpdate{ScanId: scan.ScanId, Snapshot: string(data)}}})
		ack := &pb.RptAck{CmdId: received.CmdId, Stage: pb.RptAck_DONE, Message: "Windows 更新发现已回报"}
		c.dedup.Put(received.CmdId, ack)
		c.pushReport(c.wrapAck(ack))
	}()
	return []*pb.RptAck{received, {CmdId: received.CmdId, Stage: pb.RptAck_RUNNING, Message: "Windows 更新发现中"}}
}

func (c *Client) reconcileWindowsUpdates() {
	if windowsupdate.ExecutionContract() == 0 {
		return
	}
	now := time.Now().Unix()
	previous := c.windowsUpdateReconcileAt.Load()
	if now-previous < 60 || !c.windowsUpdateReconcileAt.CompareAndSwap(previous, now) || !c.windowsUpdateBusy.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer c.windowsUpdateBusy.Store(false)
		for _, result := range windowsupdate.Reconcile(c.workDir) {
			c.pushReport(&pb.Report{AgentId: c.state.AgentID, ReportId: newUUID(), Ts: time.Now().UnixMilli(), Payload: &pb.Report_FixResult{FixResult: result}})
		}
	}()
}
