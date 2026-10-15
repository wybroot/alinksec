package comm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVirusActionBatchReceiptsAndOfflinePersistence(t *testing.T) {
	client := reportTestClient(t)
	client.workDir = t.TempDir()
	client.state = &State{AgentID: "fixture-agent"}
	client.dedup = newCmdDedup(1000)
	client.setChannelActive(true)
	path := filepath.Join(t.TempDir(), "harmless.sh")
	data := []byte("harmless command receipt")
	os.WriteFile(path, data, 0600)
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	command := &pb.CmdVirusAction{ExecutionContract: 2, Action: pb.CmdVirusAction_QUARANTINE, Targets: []*pb.VirusTarget{{FindingId: "1", Path: path, Sha256: hash}, {FindingId: "2", Path: filepath.Join(t.TempDir(), "missing"), Sha256: hash}}}
	acks := client.executeVirusAction(command, &pb.RptAck{CmdId: "batch"}, time.Now().UnixMilli())
	if len(acks) != 2 || acks[1].Stage != pb.RptAck_RUNNING {
		t.Fatal(acks)
	}
	select {
	case report := <-client.pendingReports:
		ack := report.GetAck()
		if ack.Stage != pb.RptAck_FAILED {
			t.Fatal(ack)
		}
		var receipt struct {
			Contract int `json:"virus_action_contract"`
			Results  []struct {
				ID      string `json:"finding_id"`
				Success bool   `json:"success"`
				QID     string `json:"quarantine_id"`
			} `json:"results"`
		}
		if json.Unmarshal([]byte(ack.Message), &receipt) != nil || receipt.Contract != 2 || len(receipt.Results) != 2 || !receipt.Results[0].Success || len(receipt.Results[0].QID) != 32 || receipt.Results[1].Success {
			t.Fatal(ack.Message)
		}
		if client.dedup.Get("batch").Message != ack.Message {
			t.Fatal("terminal receipt not retained")
		}
		client.setChannelActive(false)
		client.pushReport(report)
		stored, err := client.queue.PopAll()
		if err != nil || len(stored) != 1 || stored[0].GetAck().Message != ack.Message {
			t.Fatal("offline receipt lost", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("action never returned receipt")
	}
}
func TestOldVirusCommandsAreRejectedBeforeFileMutation(t *testing.T) {
	client := reportTestClient(t)
	cmd := &pb.CmdVirusAction{ExecutionContract: 2, Action: pb.CmdVirusAction_DELETE, Targets: []*pb.VirusTarget{{FindingId: "1"}}}
	for _, stamp := range []int64{0, time.Now().Add(-16 * time.Minute).UnixMilli(), time.Now().Add(6 * time.Minute).UnixMilli()} {
		acks := client.executeVirusAction(cmd, &pb.RptAck{CmdId: "expired"}, stamp)
		if len(acks) != 2 || acks[1].Stage != pb.RptAck_FAILED {
			t.Fatal(acks)
		}
	}
}
