package comm

import (
	"context"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/config"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func TestReportSenderExitLeavesCommandProducerChannelOpen(t *testing.T) {
	for _, reason := range []string{"transport-failure", "service-stop"} {
		t.Run(reason, func(t *testing.T) {
			c := reportTestClient(t)
			c.state = &State{AgentID: "shutdown-regression"}
			c.cfg = &config.Config{HeartbeatInterval: time.Hour, DrainRatePerSec: 1}
			stream := &upgradeStream{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if reason == "transport-failure" {
				stream.failAt = 1
			} else {
				cancel()
			}
			reports := make(chan *pb.Report, 1)
			finished := c.startReportSender(ctx, stream, reports, 0)
			select {
			case err := <-finished:
				if err == nil {
					t.Fatal("sender did not retain transport/cancellation error")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("sender did not finish")
			}
			// Observe sender completion before a command handler finishes its ACK.
			if _, open := <-finished; open {
				t.Fatal("sender completion was not closed")
			}
			select {
			case _, open := <-reports:
				if !open {
					t.Fatal("sender closed a channel still owned by command producers")
				}
			default:
			}
			reports <- &pb.Report{Payload: &pb.Report_Ack{Ack: &pb.RptAck{CmdId: "command-finishing-during-stop"}}}
		})
	}
}
