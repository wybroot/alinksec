package comm

import (
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"google.golang.org/protobuf/proto"
	"os"
	"path/filepath"
	"testing"
)

func TestScapFinalJournalSurvivesRestartAndRejectsChangedCommandAndCorruption(t *testing.T) {
	work := t.TempDir()
	first := &Client{workDir: work}
	command := &pb.CmdScapScan{TaskId: "task", ContentSha256: "original"}
	if previous, err := first.scapFinal("command", command, nil); err != nil || previous != nil {
		t.Fatal(previous, err)
	}
	ack := &pb.RptAck{CmdId: "command", Stage: pb.RptAck_DONE, Message: "complete native evidence exists separately"}
	if _, err := first.scapFinal("command", command, ack); err != nil {
		t.Fatal(err)
	}
	restarted := &Client{workDir: work}
	if previous, err := restarted.scapFinal("command", command, nil); err != nil || !proto.Equal(ack, previous) {
		t.Fatal(previous, err)
	}
	command.ContentSha256 = "changed"
	if _, err := restarted.scapFinal("command", command, nil); err == nil {
		t.Fatal("same command ID accepted different content")
	}
	if err := os.WriteFile(filepath.Join(work, "scap-state", "commands.json"), []byte("invalid interrupted storage"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.scapFinal("different-command", command, nil); err == nil {
		t.Fatal("corrupt journal allowed execution")
	}
}
