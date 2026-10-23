package comm

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/config"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/securestate"
	"google.golang.org/protobuf/proto"
)

func TestEvidenceExpiryRemovesStoredBytesWhileRetainingAndReplayingLiveFile(t *testing.T) {
	c := evidenceClient(t)
	path, _, err := c.evidenceJournal()
	if err != nil {
		t.Fatal(err)
	}
	command := &pb.CmdEvidenceCollect{RequestId: "11111111-1111-4111-8111-111111111111", ExecutionContract: 1, Kind: "diagnostic"}
	report := &pb.Report{AgentId: c.state.AgentID, ReportId: command.RequestId + "-evidence", Payload: &pb.Report_Evidence{Evidence: &pb.RptEvidence{RequestId: command.RequestId, CommandId: "22222222-2222-4222-8222-222222222222", Content: []byte("expired private file bytes")}}}
	expired, err := proto.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	live := proto.Clone(report).(*pb.Report)
	live.ReportId = "33333333-3333-4333-8333-333333333333-evidence"
	live.GetEvidence().RequestId = "33333333-3333-4333-8333-333333333333"
	live.GetEvidence().CommandId = "44444444-4444-4444-8444-444444444444"
	live.GetEvidence().Content = []byte("live private file bytes")
	current, err := proto.Marshal(live)
	if err != nil {
		t.Fatal(err)
	}
	past, future := time.Now().Add(-time.Hour).UnixMilli(), time.Now().Add(time.Hour).UnixMilli()
	journal := &evidenceJournal{Schema: 1, Records: []evidenceRecord{
		{CommandDigest: evidenceCommandDigest(command), ExpiresAt: past, Report: expired},
		{CommandDigest: evidenceCommandDigest(command), ExpiresAt: future, Report: current},
	}, Completed: []evidenceCompletion{
		{CommandID: "55555555-5555-4555-8555-555555555555", CommandDigest: evidenceCommandDigest(command), ExpiresAt: past},
		{CommandID: "66666666-6666-4666-8666-666666666666", CommandDigest: evidenceCommandDigest(command), ExpiresAt: future},
	}}
	if err := securestate.WriteJSONLimit(path, journal, 4<<20); err != nil {
		t.Fatal(err)
	}
	stream := &upgradeStream{}
	if err := c.sendEvidenceResults(stream, 0, map[string]time.Time{}); err != nil {
		t.Fatal(err)
	}
	if len(stream.reports) != 1 || !proto.Equal(stream.reports[0], live) {
		t.Fatal("expiry discarded the live file or replayed expired bytes")
	}
	stored := new(evidenceJournal)
	if err := securestate.ReadJSONLimit(path, stored, 4<<20); err != nil {
		t.Fatal(err)
	}
	if len(stored.Records) != 1 || !bytes.Equal(stored.Records[0].Report, current) || len(stored.Completed) != 1 || stored.Completed[0].ExpiresAt != future {
		t.Fatal("expiry left private bytes or removed a live completion on disk")
	}
	assertEvidenceJournalPrivate(t, path)
}

func TestEvidenceOutboxReplaysSameBytesAcrossRestartUntilExactAuthenticatedReceipt(t *testing.T) {
	c := evidenceClient(t)
	command := &pb.CmdEvidenceCollect{RequestId: "11111111-1111-4111-8111-111111111111", ExecutionContract: 1, Kind: "diagnostic", Deadline: time.Now().Add(time.Minute).UnixMilli()}
	ack := &pb.RptAck{CmdId: "22222222-2222-4222-8222-222222222222"}
	if got := c.executeEvidence(command, ack); got[len(got)-1].Stage != pb.RptAck_RUNNING {
		t.Fatal(got)
	}
	deadline := time.Now().Add(5 * time.Second)
	for c.bulkBusy.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if c.bulkBusy.Load() {
		t.Fatal("worker timeout")
	}
	restarted := evidenceClient(t)
	restarted.workDir = c.workDir
	previous, err := restarted.previousEvidence(ack.CmdId, command)
	if err != nil || previous.GetStage() != pb.RptAck_DONE {
		t.Fatal("restart lost completion", previous, err)
	}
	changed := proto.Clone(command).(*pb.CmdEvidenceCollect)
	changed.Kind = "quarantine_sample"
	if _, err := restarted.previousEvidence(ack.CmdId, changed); err == nil {
		t.Fatal("same command ID rebound to another request")
	}
	stream := &upgradeStream{}
	if err := restarted.sendEvidenceResults(stream, 0, map[string]time.Time{}); err != nil {
		t.Fatal(err)
	}
	if len(stream.reports) != 1 || stream.reports[0].GetEvidence() == nil {
		t.Fatal("restart did not replay actual file")
	}
	result := stream.reports[0].GetEvidence()
	if err := restarted.evidenceReceipt(&pb.CmdEvidenceReceipt{RequestId: result.RequestId, CommandId: result.CommandId, ContentSha256: strings.Repeat("0", 64)}); err != nil {
		t.Fatal(err)
	}
	_, journal, err := restarted.evidenceJournal()
	if err != nil || len(journal.Records) != 1 {
		t.Fatal("wrong receipt removed file")
	}
	second := &upgradeStream{}
	if err := restarted.sendEvidenceResults(second, 0, map[string]time.Time{}); err != nil {
		t.Fatal(err)
	}
	if len(second.reports) != 1 || !proto.Equal(stream.reports[0], second.reports[0]) {
		t.Fatal("replay changed collected bytes")
	}
	if err := restarted.evidenceReceipt(&pb.CmdEvidenceReceipt{RequestId: result.RequestId, CommandId: result.CommandId, ContentSha256: result.Sha256}); err != nil {
		t.Fatal(err)
	}
	_, journal, err = restarted.evidenceJournal()
	if err != nil || len(journal.Records) != 0 {
		t.Fatal("committed receipt did not clear outbox")
	}
	final, err := restarted.previousEvidence(ack.CmdId, command)
	if err != nil || final.GetStage() != pb.RptAck_DONE {
		t.Fatal("receipt lost immutable completion after restart", err)
	}
}

func evidenceClient(t *testing.T) *Client {
	c := reportTestClient(t)
	c.state = &State{AgentID: "fixture-agent"}
	c.cfg = &config.Config{}
	c.workDir = t.TempDir()
	c.dedup = newCmdDedup(100)
	return c
}

func TestDiagnosticZIPUsesFixedAllowlistAndNeverContainsPrivateConfiguration(t *testing.T) {
	c := evidenceClient(t)
	const secret = "private-fixture-token-not-for-diagnostics"
	t.Setenv("EVIDENCE_FIXTURE_SECRET", secret)
	if err := os.WriteFile(c.workDir+"/client.key", []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := c.diagnosticZIP("request-fixture")
	if err != nil {
		t.Fatal(err)
	}
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if len(z.File) != 3 {
		t.Fatal("unexpected diagnostic files")
	}
	names := map[string]bool{}
	for _, f := range z.File {
		names[f.Name] = true
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(content, []byte(secret)) {
			t.Fatal("private data escaped")
		}
		if f.Name == "runtime.json" {
			var identity map[string]any
			if json.Unmarshal(content, &identity) != nil || identity["agentId"] != "fixture-agent" || identity["requestId"] != "request-fixture" {
				t.Fatal("diagnostic identity missing")
			}
		}
	}
	for _, name := range []string{"runtime.json", "heartbeat.json", "README.txt"} {
		if !names[name] {
			t.Fatal("missing", name)
		}
	}
}

func TestEvidenceWorkerQueuesActualBytesBeforeCompletionAndSurvivesQueueReopen(t *testing.T) {
	c := evidenceClient(t)
	request := &pb.CmdEvidenceCollect{RequestId: "11111111-1111-4111-8111-111111111111", ExecutionContract: 1, Kind: "diagnostic", Deadline: time.Now().Add(time.Minute).UnixMilli()}
	ack := &pb.RptAck{CmdId: "22222222-2222-4222-8222-222222222222", Stage: pb.RptAck_RECEIVED}
	result := c.executeEvidence(request, ack)
	if len(result) != 2 || result[1].Stage != pb.RptAck_RUNNING {
		t.Fatal(result)
	}
	deadline := time.Now().Add(5 * time.Second)
	for c.bulkBusy.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if c.bulkBusy.Load() {
		t.Fatal("worker did not finish")
	}
	q := &OfflineQueue{path: c.queue.path}
	reports, err := q.PopAll()
	if err != nil || len(reports) != 2 {
		t.Fatalf("reports=%v error=%v", reports, err)
	}
	if !reports[0].GetEvidence().ProtoReflect().IsValid() || reports[1].GetAck().GetStage() != pb.RptAck_DONE {
		t.Fatal("completion preceded durable evidence")
	}
	evidence := reports[0].GetEvidence()
	if len(evidence.Content) == 0 || len(evidence.Sha256) != 64 || evidence.CommandId != ack.CmdId || reports[0].ReportId != request.RequestId+"-evidence" {
		t.Fatal("missing actual bound bytes")
	}
	encoded, err := proto.Marshal(reports[0])
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(pb.Report)
	if proto.Unmarshal(encoded, decoded) != nil || !proto.Equal(decoded, reports[0]) {
		t.Fatal("new protocol cannot round trip")
	}
}

func TestEvidenceRejectsExpiredArbitraryAndConcurrentCollection(t *testing.T) {
	c := evidenceClient(t)
	ack := &pb.RptAck{CmdId: "22222222-2222-4222-8222-222222222222"}
	valid := &pb.CmdEvidenceCollect{RequestId: "11111111-1111-4111-8111-111111111111", ExecutionContract: 1, Kind: "diagnostic", Deadline: time.Now().Add(time.Minute).UnixMilli()}
	for _, change := range []func(*pb.CmdEvidenceCollect){func(r *pb.CmdEvidenceCollect) { r.Kind = "file" }, func(r *pb.CmdEvidenceCollect) { r.Deadline = 1 }, func(r *pb.CmdEvidenceCollect) { r.ExecutionContract = 2 }, func(r *pb.CmdEvidenceCollect) { r.OriginalPath = "/etc/shadow" }, func(r *pb.CmdEvidenceCollect) { r.RequestId = strings.Repeat("x", 36) }} {
		r := proto.Clone(valid).(*pb.CmdEvidenceCollect)
		change(r)
		acks := c.executeEvidence(r, ack)
		if acks[len(acks)-1].Stage != pb.RptAck_FAILED {
			t.Fatal("invalid evidence command accepted", r)
		}
	}
	c.bulkBusy.Store(true)
	acks := c.executeEvidence(valid, ack)
	if acks[len(acks)-1].Stage != pb.RptAck_FAILED {
		t.Fatal("overlapping bulk work accepted")
	}
}
