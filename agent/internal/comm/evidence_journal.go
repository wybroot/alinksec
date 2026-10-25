package comm

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/securestate"
	"google.golang.org/protobuf/proto"
)

type evidenceRecord struct {
	CommandDigest string
	ExpiresAt     int64
	Report        []byte
}
type evidenceJournal struct {
	Schema    int
	Records   []evidenceRecord
	Completed []evidenceCompletion
}
type evidenceCompletion struct {
	CommandID     string
	CommandDigest string
	Failed        bool
	ExpiresAt     int64
}

func (c *Client) evidenceJournal() (string, *evidenceJournal, error) {
	dir := filepath.Join(c.workDir, "evidence-state")
	if err := securestate.PrivateDir(dir); err != nil {
		return "", nil, err
	}
	path := filepath.Join(dir, "pending.json")
	journal := &evidenceJournal{Schema: 1}
	if err := securestate.ReadJSONLimit(path, journal, 4<<20); err != nil && !os.IsNotExist(err) {
		return "", nil, err
	}
	if journal.Schema != 1 || len(journal.Records) > 2 || len(journal.Completed) > 1000 {
		return "", nil, errors.New("invalid evidence journal")
	}
	originalRecords, originalCompleted := len(journal.Records), len(journal.Completed)
	seen := map[string]bool{}
	retained := []evidenceRecord{}
	for _, record := range journal.Records {
		r := new(pb.Report)
		if len(record.Report) > maxEvidenceBytes+8192 || len(record.CommandDigest) != 64 || proto.Unmarshal(record.Report, r) != nil || r.GetEvidence() == nil ||
			!evidenceUUID.MatchString(r.GetEvidence().RequestId) || !evidenceUUID.MatchString(r.GetEvidence().CommandId) || seen[r.GetEvidence().RequestId] ||
			r.AgentId != c.state.AgentID || r.ReportId != r.GetEvidence().RequestId+"-evidence" || record.ExpiresAt <= 0 {
			return "", nil, errors.New("invalid evidence journal record")
		}
		seen[r.GetEvidence().RequestId] = true
		if record.ExpiresAt > time.Now().UnixMilli() {
			retained = append(retained, record)
		}
	}
	journal.Records = retained
	completed := []evidenceCompletion{}
	for _, record := range journal.Completed {
		if !evidenceUUID.MatchString(record.CommandID) || len(record.CommandDigest) != 64 || record.ExpiresAt <= 0 {
			return "", nil, errors.New("invalid evidence completion journal")
		}
		if record.ExpiresAt > time.Now().UnixMilli() {
			completed = append(completed, record)
		}
	}
	journal.Completed = completed
	if len(journal.Records) != originalRecords || len(journal.Completed) != originalCompleted {
		if err := securestate.WriteJSONLimit(path, journal, 4<<20); err != nil {
			return "", nil, err
		}
	}
	return path, journal, nil
}

func evidenceCommandDigest(command *pb.CmdEvidenceCollect) string {
	data, _ := proto.Marshal(command)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (c *Client) saveEvidence(command *pb.CmdEvidenceCollect, report *pb.Report) error {
	c.evidenceMu.Lock()
	defer c.evidenceMu.Unlock()
	path, journal, err := c.evidenceJournal()
	if err != nil {
		return err
	}
	if len(journal.Records) >= 2 {
		return errors.New("evidence journal full")
	}
	data, err := proto.Marshal(report)
	if err != nil {
		return err
	}
	journal.Records = append(journal.Records, evidenceRecord{CommandDigest: evidenceCommandDigest(command), ExpiresAt: command.Deadline + int64(time.Hour/time.Millisecond), Report: data})
	return securestate.WriteJSONLimit(path, journal, 4<<20)
}

// Replaying a pending command never recollects a different diagnostic snapshot.
func (c *Client) previousEvidence(id string, command *pb.CmdEvidenceCollect) (*pb.RptAck, error) {
	c.evidenceMu.Lock()
	defer c.evidenceMu.Unlock()
	_, journal, err := c.evidenceJournal()
	if err != nil {
		return nil, err
	}
	for _, record := range journal.Completed {
		if record.CommandID == id {
			if record.CommandDigest != evidenceCommandDigest(command) {
				return nil, errors.New("evidence command changed")
			}
			ack := &pb.RptAck{CmdId: id, Stage: pb.RptAck_DONE, Message: "evidence receipt already committed"}
			if record.Failed {
				ack.Stage = pb.RptAck_FAILED
				ack.Code = 1
				ack.Message = "collection_unavailable_or_limit_exceeded"
			}
			return ack, nil
		}
	}
	for _, record := range journal.Records {
		r := new(pb.Report)
		_ = proto.Unmarshal(record.Report, r)
		if r.GetEvidence().CommandId == id {
			if record.CommandDigest != evidenceCommandDigest(command) {
				return nil, errors.New("evidence command changed")
			}
			ack := &pb.RptAck{CmdId: id, Stage: pb.RptAck_DONE, Message: "evidence retained for authenticated receipt"}
			if r.GetEvidence().ErrorCode != "" {
				ack.Stage = pb.RptAck_FAILED
				ack.Code = 1
				ack.Message = r.GetEvidence().ErrorCode
			}
			return ack, nil
		}
	}
	return nil, nil
}

func (c *Client) evidenceReceipt(receipt *pb.CmdEvidenceReceipt) error {
	c.evidenceMu.Lock()
	defer c.evidenceMu.Unlock()
	path, journal, err := c.evidenceJournal()
	if err != nil {
		return err
	}
	kept := []evidenceRecord{}
	for _, record := range journal.Records {
		r := new(pb.Report)
		_ = proto.Unmarshal(record.Report, r)
		result := r.GetEvidence()
		if result.RequestId != receipt.RequestId || result.CommandId != receipt.CommandId || result.Sha256 != receipt.ContentSha256 {
			kept = append(kept, record)
		} else {
			if len(journal.Completed) >= 1000 {
				journal.Completed = journal.Completed[1:]
			}
			journal.Completed = append(journal.Completed, evidenceCompletion{CommandID: result.CommandId, CommandDigest: record.CommandDigest, Failed: result.ErrorCode != "", ExpiresAt: time.Now().Add(30 * 24 * time.Hour).UnixMilli()})
		}
	}
	journal.Records = kept
	return securestate.WriteJSONLimit(path, journal, 4<<20)
}

func (c *Client) sendEvidenceResults(stream pb.AgentChannel_ChannelClient, generation uint64, sent map[string]time.Time) error {
	if c.workDir == "" {
		return nil
	}
	c.evidenceMu.Lock()
	_, journal, err := c.evidenceJournal()
	c.evidenceMu.Unlock()
	if err != nil {
		c.log.Error("evidence journal unavailable", "err", err)
		return nil
	}
	retained := map[string]bool{}
	for _, record := range journal.Records {
		r := new(pb.Report)
		_ = proto.Unmarshal(record.Report, r)
		retained[r.ReportId] = true
	}
	for id := range sent {
		if !retained[id] {
			delete(sent, id)
		}
	}
	for _, record := range journal.Records {
		r := new(pb.Report)
		_ = proto.Unmarshal(record.Report, r)
		if time.Since(sent[r.ReportId]) < 15*time.Second {
			continue
		}
		if err := c.sendReport(stream, r, generation); err != nil {
			return err
		}
		sent[r.ReportId] = time.Now()
	}
	return nil
}
