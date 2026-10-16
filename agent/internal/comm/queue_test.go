package comm

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func TestQueuePeekFailureCompactionAndRestart(t *testing.T) {
	q, err := NewOfflineQueue(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b", "c"} {
		if err := q.Push(securityReport(id)); err != nil {
			t.Fatal(err)
		}
	}
	first, err := q.Peek()
	if err != nil || first.ReportId != "a" {
		t.Fatal("peek", err)
	}
	q.Release()
	retry, err := q.Peek()
	if err != nil || retry.ReportId != "a" {
		t.Fatal("failed send lost data")
	}
	q.lastCompaction = time.Time{}
	if err := q.Push(securityReport("d")); err != nil {
		t.Fatal(err)
	}
	q.Ack()
	if err := q.Push(securityReport("e")); err != nil {
		t.Fatal(err)
	}
	// The forced streaming compaction removes the acknowledged prefix. Reopen
	// from disk must retain every unacknowledged record in order.
	reopened := &OfflineQueue{path: q.path}
	for _, id := range []string{"b", "c", "d", "e"} {
		r, err := reopened.Peek()
		if err != nil || r == nil || r.ReportId != id {
			t.Fatalf("want %s, got %v %v", id, r, err)
		}
		reopened.Ack()
	}
	if r, err := reopened.Peek(); err != nil || r != nil {
		t.Fatal("queue did not finish")
	}
	st, err := os.Stat(q.path)
	if err != nil || st.Size() != 0 {
		t.Fatal("drained file not reclaimed")
	}
}

func TestQueueLargeBacklogAndMalformedOversizePreservesSource(t *testing.T) {
	q, err := NewOfflineQueue(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(q.path)
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriter(f)
	for i := 0; i < 512; i++ {
		if _, err := fmt.Fprintf(w, "{\"reportId\":\"%d\",\"securityEvent\":{\"detail\":\"%s\"}}\n", i, strings.Repeat("x", 16<<10)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	for i := 0; i < 3; i++ {
		r, err := q.Peek()
		if err != nil || r == nil || r.ReportId != fmt.Sprint(i) {
			t.Fatal("bounded replay", err)
		}
		q.Ack()
	}
	if err := q.Push(securityReport("last")); err != nil {
		t.Fatal(err)
	}
	r, err := q.Peek()
	if err != nil || r.ReportId != "3" {
		t.Fatal("stream compaction lost cursor", err)
	}
	q.Release()
	oversized := strings.Repeat("z", maxRecordBytes+1) + "\n"
	if err := os.WriteFile(q.path, []byte(oversized), 0600); err != nil {
		t.Fatal(err)
	}
	q.offset = 0
	q.lastCompaction = time.Time{}
	if _, err := q.Peek(); err == nil {
		t.Fatal("oversized record accepted")
	}
	if err := q.compactLocked(); err == nil {
		t.Fatal("oversized compaction silently truncated source")
	}
	st, err := os.Stat(q.path)
	if err != nil || st.Size() != int64(len(oversized)) {
		t.Fatal("failed compaction changed original")
	}
}

func TestOfflineQueuePrunesExpiredReportsBeforeReachingCapacity(t *testing.T) {
	queue, err := NewOfflineQueue(t.TempDir())
	if err != nil {
		t.Fatalf("NewOfflineQueue() error = %v", err)
	}
	if err := queue.Push(&pb.Report{Ts: time.Now().Add(-maxEntryAge - time.Minute).UnixMilli()}); err != nil {
		t.Fatalf("Push(expired) error = %v", err)
	}
	if err := queue.Push(&pb.Report{Ts: time.Now().UnixMilli()}); err != nil {
		t.Fatalf("Push(current) error = %v", err)
	}

	reports, err := queue.PopAll()
	if err != nil {
		t.Fatalf("PopAll() error = %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("PopAll() returned %d reports, want 1", len(reports))
	}
}

// PopAll is a small-fixture helper, deliberately absent from production.
func (q *OfflineQueue) PopAll() ([]*pb.Report, error) {
	var out []*pb.Report
	for {
		r, err := q.Peek()
		if err != nil {
			return out, err
		}
		if r == nil {
			return out, nil
		}
		out = append(out, r)
		q.Ack()
	}
}
