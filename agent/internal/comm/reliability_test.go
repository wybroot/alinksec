package comm

import (
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestBusinessReportPersistsBeforeSendAndNeedsMatchingReceipt(t *testing.T) {
	dir := t.TempDir()
	q, err := NewOfflineQueue(dir)
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{queue: q, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	c.pushReport(&pb.Report{AgentId: "agent", ReportId: "one", Payload: &pb.Report_SecurityEvent{SecurityEvent: &pb.RptSecurityEvent{Type: "process"}}})
	reopened, err := NewOfflineQueue(dir)
	if err != nil {
		t.Fatal(err)
	}
	r, err := reopened.Peek()
	if err != nil || r == nil || !r.Reliable {
		t.Fatalf("persisted report: %v %v", r, err)
	}
	if !reopened.ShouldSend("one") || reopened.ShouldSend("one") {
		t.Fatal("replay interval not bounded")
	}
	if reopened.Receipt("other") {
		t.Fatal("unmatched receipt advanced queue")
	}
	if r, _ := reopened.Peek(); r == nil {
		t.Fatal("send removed unacknowledged report")
	}
	// A new process/connection replays the report when no receipt was persisted.
	afterCrash, err := NewOfflineQueue(dir)
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := afterCrash.Peek(); r == nil || r.ReportId != "one" {
		t.Fatal("report lost on restart")
	}
	if !reopened.Receipt("one") {
		t.Fatal("matching receipt not accepted")
	}
	if r, _ := reopened.Peek(); r != nil {
		t.Fatal("committed report not dequeued")
	}
}
func TestAssetSequencePersistsAcrossRestartAndRejectsCorruptState(t *testing.T) {
	dir := t.TempDir()
	first, err := reserveAssetSequence(dir, "agent")
	if err != nil {
		t.Fatal(err)
	}
	second, err := reserveAssetSequence(dir, "agent")
	if err != nil || second <= first {
		t.Fatalf("sequence %d %d %v", first, second, err)
	}
	if _, err := reserveAssetSequence(dir, "different-agent"); err == nil {
		t.Fatal("identity mismatch accepted")
	}
	if err := os.Remove(filepath.Join(dir, "asset-sequence.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := reserveAssetSequence(dir, "agent"); err == nil {
		t.Fatal("missing initialized counter was reset")
	}
	if err := os.WriteFile(filepath.Join(dir, "asset-sequence.json"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := reserveAssetSequence(dir, "agent"); err == nil {
		t.Fatal("corrupt sequence state accepted")
	}

	if err := os.WriteFile(filepath.Join(dir, "asset-sequence.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := reserveAssetSequence(dir, "agent"); err == nil {
		t.Fatal("schema-incomplete sequence state accepted")
	}
}

func TestSenderRetainsSuccessfulSendsUntilDurableReceipt(t *testing.T) {
	q, err := NewOfflineQueue(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{queue: q, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	c.pushReport(&pb.Report{AgentId: "agent", ReportId: "report", Payload: &pb.Report_SecurityEvent{SecurityEvent: &pb.RptSecurityEvent{Type: "process"}}})
	stream := &upgradeStream{}
	if sent, err := c.drainQueue(stream, 0); err != nil || sent {
		t.Fatal("sent before receipt capability negotiation")
	}
	c.receiptsSupported.Store(true)
	stream.failAt = 1
	if _, err := c.drainQueue(stream, 0); err == nil {
		t.Fatal("send failure hidden")
	}
	if r, _ := q.Peek(); r == nil {
		t.Fatal("failed send lost report")
	}
	if sent, err := c.drainQueue(stream, 0); err != nil || !sent {
		t.Fatalf("send %v %v", sent, err)
	}
	if r, _ := q.Peek(); r == nil {
		t.Fatal("transport success removed uncommitted report")
	}
	if len(stream.reports) != 1 || !stream.reports[0].Reliable {
		t.Fatal("durable receipt not requested")
	}
	if !q.Receipt("report") {
		t.Fatal("receipt rejected")
	}
	if r, _ := q.Peek(); r != nil {
		t.Fatal("committed report still pending")
	}
}
