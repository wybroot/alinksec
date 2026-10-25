//go:build windows

package comm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/securestate"
	"golang.org/x/sys/windows"
	"google.golang.org/protobuf/proto"
)

// Exercise the actual receipt transaction while a reader holds the old record.
// The legacy reader is a positive control, not a simulated filesystem error.
func TestEvidenceReceiptObserverSharing(t *testing.T) {
	for _, legacy := range []bool{true, false} {
		name := "shared_snapshot_allows_commit"
		if legacy {
			name = "legacy_observer_blocks_commit"
		}
		t.Run(name, func(t *testing.T) {
			c := evidenceClient(t)
			command := &pb.CmdEvidenceCollect{RequestId: "11111111-1111-4111-8111-111111111111", Kind: "diagnostic", ExecutionContract: 1, Deadline: time.Now().Add(time.Minute).UnixMilli()}
			content := []byte("immutable evidence observer fixture")
			sum := sha256.Sum256(content)
			result := &pb.RptEvidence{RequestId: command.RequestId, CommandId: "22222222-2222-4222-8222-222222222222", Kind: command.Kind, ExecutionContract: 1, Content: content, Sha256: hex.EncodeToString(sum[:])}
			report := &pb.Report{AgentId: c.state.AgentID, ReportId: command.RequestId + "-evidence", Payload: &pb.Report_Evidence{Evidence: result}}
			if err := c.saveEvidence(command, report); err != nil {
				t.Fatal(err)
			}
			path, _, err := c.evidenceJournal()
			if err != nil {
				t.Fatal(err)
			}
			var observer *os.File
			if legacy {
				observer, err = os.Open(path)
			} else {
				var p *uint16
				p, err = windows.UTF16PtrFromString(path)
				if err == nil {
					var h windows.Handle
					h, err = windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
					if err == nil {
						observer = os.NewFile(uintptr(h), path)
					}
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			defer observer.Close()
			receipt := &pb.CmdEvidenceReceipt{RequestId: result.RequestId, CommandId: result.CommandId, ContentSha256: result.Sha256}
			err = c.evidenceReceipt(receipt)
			if legacy {
				if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
					t.Fatalf("ordinary observer did not reproduce the actual receipt sharing conflict: %v", err)
				}
				t.Logf("ordinary observer blocked actual receipt persistence: %v", err)
				var retained evidenceJournal
				if err := securestate.ReadJSONLimit(path, &retained, 4<<20); err != nil {
					t.Fatal(err)
				}
				encoded, err := proto.Marshal(report)
				if err != nil || len(retained.Records) != 1 || len(retained.Completed) != 0 || !bytes.Equal(retained.Records[0].Report, encoded) {
					t.Fatal("failed receipt transaction lost evidence or claimed a commit", err)
				}
				stream := &upgradeStream{}
				if err := c.sendEvidenceResults(stream, 0, map[string]time.Time{}); err != nil || len(stream.reports) != 1 || !proto.Equal(stream.reports[0], report) {
					t.Fatal("failed commit no longer replays identical evidence", err)
				}
				if err := observer.Close(); err != nil {
					t.Fatal(err)
				}
				if err := c.evidenceReceipt(receipt); err != nil {
					t.Fatalf("exact receipt did not recover after the observer closed: %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("shared snapshot blocked actual receipt commit: %v", err)
				}
				var snapshot evidenceJournal
				encoded, err := proto.Marshal(report)
				if err != nil {
					t.Fatal(err)
				}
				if err := json.NewDecoder(observer).Decode(&snapshot); err != nil || len(snapshot.Records) != 1 || len(snapshot.Completed) != 0 || !bytes.Equal(snapshot.Records[0].Report, encoded) {
					t.Fatal("open snapshot was torn or rebound to the new journal", err)
				}
			}
			var committed evidenceJournal
			if err := securestate.ReadJSONLimit(path, &committed, 4<<20); err != nil || len(committed.Records) != 0 || len(committed.Completed) != 1 || committed.Completed[0].CommandID != result.CommandId || committed.Completed[0].CommandDigest != evidenceCommandDigest(command) || committed.Completed[0].Failed {
				t.Fatal("receipt did not persist the exact immutable completion", err)
			}
			ack, err := c.previousEvidence(result.CommandId, command)
			if err != nil || ack.GetStage() != pb.RptAck_DONE {
				t.Fatal("committed receipt lost duplicate command completion", err)
			}
			assertEvidenceJournalPrivate(t, path)
		})
	}
}
