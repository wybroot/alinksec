package comm

import (
	"testing"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

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
