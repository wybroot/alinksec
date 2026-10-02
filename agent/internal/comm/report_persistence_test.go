package comm

import (
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func reportTestClient(t *testing.T) *Client {
	t.Helper()
	queue, err := NewOfflineQueue(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &Client{queue: queue, pendingReports: make(chan *pb.Report, 4),
		log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func securityReport(id string) *pb.Report {
	return &pb.Report{ReportId: id, Payload: &pb.Report_SecurityEvent{
		SecurityEvent: &pb.RptSecurityEvent{Type: "process"}}}
}

func TestOfflineReportsPersistBelowBufferCapacityAndSurviveReopen(t *testing.T) {
	client := reportTestClient(t)
	client.pushReport(securityReport("offline"))
	queue := &OfflineQueue{path: client.queue.path}
	reports, err := queue.PopAll()
	if err != nil || len(reports) != 1 || reports[0].ReportId != "offline" {
		t.Fatalf("reopened queue = %v, error = %v", reports, err)
	}
	if len(client.pendingReports) != 0 {
		t.Fatal("offline report remained in volatile memory")
	}
}

func TestDisconnectPersistsPendingBusinessReportsAndDropsMetrics(t *testing.T) {
	client := reportTestClient(t)
	client.setChannelActive(true)
	client.pushReport(securityReport("before-disconnect"))
	client.pendingReports <- &pb.Report{Payload: &pb.Report_Metrics{Metrics: &pb.RptMetricsBatch{}}}
	client.setChannelActive(false)
	client.pushReport(securityReport("after-disconnect"))
	reports, err := client.queue.PopAll()
	if err != nil || len(reports) != 2 {
		t.Fatalf("persisted reports = %v, error = %v", reports, err)
	}
	if reports[0].ReportId != "before-disconnect" || reports[1].ReportId != "after-disconnect" {
		t.Fatal("disconnect lost or reordered business reports")
	}
}

func TestConcurrentDisconnectDoesNotLoseReports(t *testing.T) {
	client := reportTestClient(t)
	client.setChannelActive(true)
	var workers sync.WaitGroup
	for i := 0; i < 20; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			client.pushReport(securityReport(fmt.Sprint(i)))
		}(i)
	}
	client.setChannelActive(false)
	workers.Wait()
	reports, err := client.queue.PopAll()
	if err != nil || len(reports) != 20 {
		t.Fatalf("persisted reports = %d, error = %v", len(reports), err)
	}
	ids := make(map[string]bool)
	for _, report := range reports {
		if ids[report.ReportId] {
			t.Fatal("duplicate report")
		}
		ids[report.ReportId] = true
	}
}
