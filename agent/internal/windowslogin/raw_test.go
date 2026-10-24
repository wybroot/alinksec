package windowslogin

import (
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestRawSinkUsesSameCursorWithProtectionDisabledAndRetriesBeforeCommit(t *testing.T) {
	r := &fakeReader{success: true, failure: true}
	at := time.Now()
	r.add(t, at, 1, 4625, 3, "192.0.2.8", "first")
	e := newEngine(t.TempDir(), "example:443", slog.New(slog.NewTextHandler(io.Discard, nil)), r, &fakeFirewall{})
	defer e.firewall.Close()
	var got []*pb.LogLine
	accept := false
	e.SetRawSink(func(lines []*pb.LogLine) bool { got = append(got, lines...); return accept })
	e.Update(nil)
	e.Poll()
	if e.s.Cursor != 1 {
		t.Fatal("initial tail baseline not established")
	}
	r.add(t, at, 2, 4625, 3, "192.0.2.8", "second")
	e.Poll()
	if e.s.Cursor != 1 || e.Status().Issue != "raw_log_queue_failed" || len(got) != 1 {
		t.Fatal("failed admission advanced cursor")
	}
	key := got[0].Fields["source_event_id"]
	accept = true
	e.Poll()
	if e.s.Cursor != 2 || len(got) != 2 || got[1].Fields["source_event_id"] != key || got[1].Content != r.records[1].RawXML || got[1].Fields["timestamp_kind"] != "event" {
		t.Fatal("raw retry or native XML changed")
	}
	e.Poll()
	if len(got) != 2 {
		t.Fatal("committed cursor replayed")
	}
	if e.Status().State != "disabled" {
		t.Fatal("raw collection enabled protection")
	}
}
func TestRawAdmissionSplitsLargeNativeXmlWithoutAdvancingPastRejection(t *testing.T) {
	var batches []int
	e := &Engine{rawSink: func(lines []*pb.LogLine) bool {
		size := 0
		for _, l := range lines {
			size += len(l.Content)
		}
		if size >= 512<<10 || len(lines) > 100 {
			t.Fatal("unbounded batch")
		}
		batches = append(batches, len(lines))
		return true
	}}
	var rows []*pb.LogLine
	for i := 0; i < 128; i++ {
		rows = append(rows, &pb.LogLine{Content: string(make([]byte, 65536))})
	}
	if !e.admitRaw(rows) || len(batches) < 16 {
		t.Fatal("large native batch not split")
	}
}
