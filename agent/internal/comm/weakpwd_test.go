package comm

import (
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"testing"
)

func TestWeakPasswordRejectsOldContractsAndUnknownDictionariesBeforeWork(t *testing.T) {
	for _, command := range []*pb.CmdVulnScan{{}, {ExecutionContract: 1, IncludeWeakPassword: true, WeakDictionaryVersion: "untrusted"}} {
		client := &Client{}
		acks := client.executeVulnScan(command, &pb.RptAck{CmdId: "fixture"})
		if len(acks) != 2 || acks[1].Stage != pb.RptAck_FAILED || client.bulkBusy.Load() || client.scanBusy.Load() {
			t.Fatal("invalid scan admitted")
		}
	}
}
