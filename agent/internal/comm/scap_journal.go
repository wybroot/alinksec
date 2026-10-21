package comm

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/scap"
	"github.com/alinksec/alinksec-agent/internal/securestate"
	"google.golang.org/protobuf/proto"
)

type scapFinalRecord struct {
	ID      string
	Content string
	Stage   pb.RptAck_Stage
	Code    int32
	Message string
}
type scapFinalJournal struct {
	Schema  int
	Records []scapFinalRecord
}

// Preserve the most recent 1000 completed read-only commands across restart.
// Interrupted commands without a final record may be safely re-executed.
// Native evidence remains in the separate report/queue path, never in this file.
func (c *Client) scapFinal(id string, command *pb.CmdScapScan, ack *pb.RptAck) (*pb.RptAck, error) {
	c.scapJournalMu.Lock()
	defer c.scapJournalMu.Unlock()
	invalid := errors.New("scap command journal invalid")
	if id == "" || len(id) > 128 || command == nil {
		return nil, invalid
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil {
		return nil, invalid
	}
	digest := scap.Digest(payload)
	directory := filepath.Join(c.workDir, "scap-state")
	if err := securestate.PrivateDir(directory); err != nil {
		return nil, invalid
	}
	path := filepath.Join(directory, "commands.json")
	journal := scapFinalJournal{Schema: 1}
	if err := securestate.ReadJSONLimit(path, &journal, 1<<20); err != nil && !os.IsNotExist(err) {
		return nil, invalid
	}
	if journal.Schema != 1 || len(journal.Records) > 1000 {
		return nil, invalid
	}
	seen := map[string]bool{}
	var previous *pb.RptAck
	for _, r := range journal.Records {
		if r.ID == "" || len(r.ID) > 128 || seen[r.ID] || len(r.Content) != 64 || strings.Trim(r.Content, "0123456789abcdef") != "" || (r.Stage != pb.RptAck_DONE && r.Stage != pb.RptAck_FAILED) || len(r.Message) > 1024 {
			return nil, invalid
		}
		seen[r.ID] = true
		if r.ID == id {
			if r.Content != digest {
				return nil, invalid
			}
			previous = &pb.RptAck{CmdId: id, Stage: r.Stage, Code: r.Code, Message: r.Message}
		}
	}
	if previous != nil || ack == nil {
		return previous, nil
	}
	if !terminal(ack) || ack.GetCmdId() != id || len(ack.Message) > 1024 {
		return nil, invalid
	}
	if len(journal.Records) == 1000 {
		journal.Records = journal.Records[1:]
	}
	journal.Records = append(journal.Records, scapFinalRecord{ID: id, Content: digest, Stage: ack.Stage, Code: ack.Code, Message: ack.Message})
	if err := securestate.WriteJSONLimit(path, journal, 1<<20); err != nil {
		return nil, invalid
	}
	return nil, nil
}
