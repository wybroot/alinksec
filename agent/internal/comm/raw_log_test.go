package comm

import (
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"google.golang.org/protobuf/proto"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
)

func TestRawLogAdmissionPersistsBeforeCursorAndRefusesUnavailableSpool(t *testing.T) {
	dir := t.TempDir()
	q, err := NewOfflineQueue(dir)
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{state: &State{AgentID: "raw-agent"}, queue: q, log: slog.New(slog.NewTextHandler(io.Discard, nil)), channelActive: true, pendingReports: make(chan *pb.Report, 1)}
	lines := []*pb.LogLine{{Ts: 1, Content: "  原文\n<Event/>", Fields: map[string]string{"source_event_id": strings.Repeat("a", 64), "timestamp_kind": "event"}}}
	if !c.queueLogBatch("windows-security", lines) || len(c.pendingReports) != 0 {
		t.Fatal("log admission used volatile online channel")
	}
	reopened, err := NewOfflineQueue(dir)
	if err != nil {
		t.Fatal(err)
	}
	report, err := reopened.Peek()
	if err != nil || report == nil || report.AgentId != "raw-agent" || report.ReportId == "" || !proto.Equal(report.GetLogBatch().Lines[0], lines[0]) {
		t.Fatal("raw spool restart changed report", err)
	}
	q.path = t.TempDir()
	if c.queueLogBatch("windows-security", lines) {
		t.Fatal("admitted unavailable spool")
	}
}

func TestRawLogBlockedSendCannotGrowPastSpoolCapacity(t *testing.T) {
	q, err := NewOfflineQueue(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(q.path)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(maxQueueBytes); err != nil {
		t.Fatal(err)
	}
	f.Close()
	q.peeked = securityReport("blocked-send")
	report := &pb.Report{AgentId: "a", ReportId: "raw", Payload: &pb.Report_LogBatch{LogBatch: &pb.RptLogBatch{Source: "secure", Lines: []*pb.LogLine{{Content: "raw"}}}}}
	if q.Push(report) == nil {
		t.Fatal("full spool admitted raw line during blocked send")
	}
	st, _ := os.Stat(q.path)
	if st.Size() != maxQueueBytes {
		t.Fatal("full spool grew")
	}
}
