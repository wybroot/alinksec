package comm

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func TestReportPriorityCoversAll14ReportPayloads(t *testing.T) {
	cases := []struct {
		name string
		r    *pb.Report
		want reportPriority
	}{
		{"heartbeat", &pb.Report{Payload: &pb.Report_Heartbeat{Heartbeat: &pb.RptHeartbeat{}}}, priorityEphemeral},
		{"isolation_state", &pb.Report{Payload: &pb.Report_IsolationState{IsolationState: &pb.RptIsolationState{}}}, priorityEphemeral},
		{"metrics", &pb.Report{Payload: &pb.Report_Metrics{Metrics: &pb.RptMetricsBatch{}}}, priorityEphemeral},
		{"log_batch", &pb.Report{Payload: &pb.Report_LogBatch{LogBatch: &pb.RptLogBatch{}}}, priorityBulk},
		{"asset", &pb.Report{Payload: &pb.Report_Asset{Asset: &pb.RptAssetSnapshot{}}}, priorityStandard},
		{"security_event", &pb.Report{Payload: &pb.Report_SecurityEvent{SecurityEvent: &pb.RptSecurityEvent{}}}, priorityCritical},
		{"ack", &pb.Report{Payload: &pb.Report_Ack{Ack: &pb.RptAck{}}}, priorityCritical},
		{"fix_result", &pb.Report{Payload: &pb.Report_FixResult{FixResult: &pb.RptFixResult{}}}, priorityCritical},
		{"virus_result", &pb.Report{Payload: &pb.Report_VirusResult{VirusResult: &pb.RptVirusResult{}}}, priorityCritical},
		{"evidence", &pb.Report{Payload: &pb.Report_Evidence{Evidence: &pb.RptEvidence{}}}, priorityCritical},
		{"scap_result", &pb.Report{Payload: &pb.Report_ScapResult{ScapResult: &pb.RptScapResult{}}}, priorityCritical},
		{"baseline_result", &pb.Report{Payload: &pb.Report_BaselineResult{BaselineResult: &pb.RptBaselineResult{}}}, priorityCritical},
		{"scan_result", &pb.Report{Payload: &pb.Report_ScanResult{ScanResult: &pb.RptScanResult{}}}, priorityCritical},
		{"windows_update", &pb.Report{Payload: &pb.Report_WindowsUpdate{WindowsUpdate: &pb.RptWindowsUpdate{}}}, priorityCritical},
	}
	for _, tc := range cases {
		if got := reportPriorityOf(tc.r); got != tc.want {
			t.Fatalf("%s priority = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func makeLogReport(id string, size int) *pb.Report {
	return &pb.Report{
		AgentId:  "agent-q",
		ReportId: id,
		Ts:       time.Now().UnixMilli(),
		Payload:  &pb.Report_LogBatch{LogBatch: &pb.RptLogBatch{Source: "secure", Lines: []*pb.LogLine{{Content: strings.Repeat("l", size)}}}},
	}
}

func makeAssetReport(id string, size int) *pb.Report {
	return &pb.Report{
		AgentId:  "agent-q",
		ReportId: id,
		Ts:       time.Now().UnixMilli(),
		Payload:  &pb.Report_Asset{Asset: &pb.RptAssetSnapshot{Processes: []*pb.ProcessInfo{{Pid: 1, Name: strings.Repeat("p", size)}}}},
	}
}

func makeVirusReport(id string) *pb.Report {
	return &pb.Report{
		AgentId:  "agent-q",
		ReportId: id,
		Ts:       time.Now().UnixMilli(),
		Payload:  &pb.Report_VirusResult{VirusResult: &pb.RptVirusResult{TaskId: id}},
	}
}

func makeAckReport(id string) *pb.Report {
	return &pb.Report{
		AgentId:  "agent-q",
		ReportId: id,
		Ts:       time.Now().UnixMilli(),
		Payload:  &pb.Report_Ack{Ack: &pb.RptAck{CmdId: id, Stage: pb.RptAck_DONE, Message: "done"}},
	}
}

func TestQueueCompactionEvictsBulkBeforeStandardBeforeCriticalAndPreservesOrder(t *testing.T) {
	t.Run("bulk_evicted_before_standard_and_critical_preserves_order", func(t *testing.T) {
		q, err := NewOfflineQueue(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		q.maxBytes = 4096
		q.criticalReserve = 1024

		seq := []*pb.Report{
			securityReport("sec-1"),
			makeLogReport("log-1", 700),
			makeAssetReport("asset-1", 500),
			makeVirusReport("virus-1"),
			makeLogReport("log-2", 700),
			makeAckReport("ack-1"),
			makeLogReport("log-3", 700),
			makeLogReport("log-4", 700),
			securityReport("sec-2"),
		}
		for _, r := range seq {
			if r.ReportId == "sec-1" || r.ReportId == "sec-2" {
				r.AgentId = "agent-q"
				r.Ts = time.Now().UnixMilli()
			}
			if err := q.Push(r); err != nil {
				t.Fatalf("Push(%s) error = %v", r.ReportId, err)
			}
		}

		stats := q.Stats()
		if stats.BulkEvicted == 0 || stats.StandardEvicted != 0 || stats.CriticalEvicted != 0 {
			t.Fatalf("unexpected eviction counters: %+v", stats)
		}

		reopened := &OfflineQueue{path: q.path, maxBytes: q.maxBytes, criticalReserve: q.criticalReserve}
		got, err := reopened.PopAll()
		if err != nil {
			t.Fatal(err)
		}
		var criticalIDs []string
		hasAsset := false
		for _, r := range got {
			if reportPriorityOf(r) >= priorityCritical {
				criticalIDs = append(criticalIDs, r.ReportId)
			}
			if r.ReportId == "asset-1" {
				hasAsset = true
			}
		}
		if !hasAsset {
			t.Fatal("standard asset report was unnecessarily evicted while bulk logs remained")
		}
		if fmt.Sprint(criticalIDs) != "[sec-1 virus-1 ack-1 sec-2]" {
			t.Fatalf("critical order corrupted or dropped: %v", criticalIDs)
		}
	})

	t.Run("standard_evicted_before_critical_and_bulk_never_evicts_critical", func(t *testing.T) {
		q, err := NewOfflineQueue(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		q.maxBytes = 4096
		q.criticalReserve = 1024 // non-critical soft cap = 3072

		// Push two standard asset reports (~1200B each) plus critical events (~1200B).
		if err := q.Push(makeAssetReport("asset-old", 1000)); err != nil {
			t.Fatal(err)
		}
		ev1 := &pb.Report{AgentId: "a", ReportId: "crit-keep-1", Ts: time.Now().UnixMilli(), Payload: &pb.Report_SecurityEvent{SecurityEvent: &pb.RptSecurityEvent{Detail: strings.Repeat("c", 500)}}}
		if err := q.Push(ev1); err != nil {
			t.Fatal(err)
		}
		if err := q.Push(makeAssetReport("asset-new", 1000)); err != nil {
			t.Fatal(err)
		}
		if err := q.Push(makeAssetReport("asset-newest", 1000)); err != nil {
			t.Fatal(err)
		}
		stats := q.Stats()
		if stats.StandardEvicted == 0 || stats.CriticalEvicted != 0 {
			t.Fatalf("expected standard eviction preserving critical, got %+v", stats)
		}

		// Now fill with critical events well past soft cap (3072). A subsequent Bulk or Standard push MUST fail without evicting any critical event!
		for i := 0; i < 4; i++ {
			ev := &pb.Report{AgentId: "a", ReportId: fmt.Sprintf("crit-fill-%d", i), Ts: time.Now().UnixMilli(), Payload: &pb.Report_SecurityEvent{SecurityEvent: &pb.RptSecurityEvent{Detail: strings.Repeat("s", 600)}}}
			if err := q.Push(ev); err != nil {
				t.Fatal(err)
			}
		}
		if err := q.Push(makeLogReport("log-blocked-by-critical", 200)); err == nil {
			t.Fatal("lower-priority log push bypassed critical protection")
		}
		if err := q.Push(makeAssetReport("asset-blocked-by-critical", 200)); err == nil {
			t.Fatal("lower-priority asset push bypassed critical protection")
		}
		if q.Stats().CapacityRejected < 2 {
			t.Fatalf("expected capacity rejections recorded, got %+v", q.Stats())
		}

		// Finally, critical ring eviction still keeps queue bounded when critical alone overflows maxBytes.
		for i := 0; i < 6; i++ {
			ev := &pb.Report{AgentId: "a", ReportId: fmt.Sprintf("crit-ring-%d", i), Ts: time.Now().UnixMilli(), Payload: &pb.Report_SecurityEvent{SecurityEvent: &pb.RptSecurityEvent{Detail: strings.Repeat("r", 700)}}}
			if err := q.Push(ev); err != nil {
				t.Fatalf("critical push failed unexpectedly: %v", err)
			}
		}
		after := q.Stats()
		if after.CriticalEvicted == 0 || after.Bytes > q.maxBytes {
			t.Fatalf("expected bounded critical ring eviction, got %+v", after)
		}
	})
}

func TestBlockedSendReservesCriticalHeadroomAgainstLogFlood(t *testing.T) {
	q, err := NewOfflineQueue(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	q.maxBytes = 4096
	q.criticalReserve = 1024 // softLimit = 3072

	if err := q.Push(securityReport("head")); err != nil {
		t.Fatal(err)
	}
	peeked, err := q.Peek()
	if err != nil || peeked == nil {
		t.Fatal("peek failed", err)
	}

	admittedLogs := 0
	for i := 0; i < 10; i++ {
		if err := q.Push(makeLogReport(fmt.Sprintf("log-%d", i), 400)); err == nil {
			admittedLogs++
		} else {
			break
		}
	}
	if admittedLogs == 0 {
		t.Fatal("expected logs to fill up to softLimit")
	}
	if q.Stats().Bytes > 3072 {
		t.Fatalf("logs exceeded softLimit: %+v", q.Stats())
	}
	if err := q.Push(makeAssetReport("asset-over-soft", 600)); err == nil {
		t.Fatal("standard report consumed critical reserve during blocked send")
	}

	// Critical event must still be admitted into reserved headroom while peeked is held!
	crit := &pb.Report{AgentId: "a", ReportId: "urgent-during-block", Ts: time.Now().UnixMilli(), Payload: &pb.Report_SecurityEvent{SecurityEvent: &pb.RptSecurityEvent{Detail: "alert"}}}
	if err := q.Push(crit); err != nil {
		t.Fatalf("critical report denied reserved headroom during blocked send: %v", err)
	}

	// Fill remaining headroom up to maxBytes with critical events; exceeding maxBytes must fail cleanly.
	var lastErr error
	for i := 0; i < 20; i++ {
		lastErr = q.Push(&pb.Report{AgentId: "a", ReportId: fmt.Sprintf("urgent-fill-%d", i), Ts: time.Now().UnixMilli(), Payload: &pb.Report_SecurityEvent{SecurityEvent: &pb.RptSecurityEvent{Detail: strings.Repeat("x", 200)}}})
		if lastErr != nil {
			break
		}
	}
	if lastErr == nil || q.Stats().Bytes > q.maxBytes {
		t.Fatalf("blocked queue exceeded maxBytes: err=%v stats=%+v", lastErr, q.Stats())
	}
}

func TestWorkdirBudgetEnforcesHardLimitFreeDiskFloorAndSafeCleanup(t *testing.T) {
	oldQuery := queryFreeDiskSpace
	t.Cleanup(func() { queryFreeDiskSpace = oldQuery })

	workDir := t.TempDir()
	qDir := filepath.Join(workDir, "virus", "quarantine")
	evDir := filepath.Join(workDir, "evidence")
	dbDir := filepath.Join(workDir, "virus", "db")
	queueDir := filepath.Join(workDir, "queue")
	for _, d := range []string{
		qDir, evDir, dbDir, queueDir,
		filepath.Join(workDir, "certs"),
		filepath.Join(workDir, "isolation"),
		filepath.Join(workDir, "upgrade", "results"),
		filepath.Join(workDir, "evidence-state"),
		filepath.Join(workDir, "scap-state"),
		filepath.Join(workDir, "windowsupdate"),
	} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
	}

	now := time.Now()
	staleTime := now.Add(-2 * time.Hour)
	veryOld := now.Add(-40 * 24 * time.Hour)

	// Protected files that MUST NEVER be deleted under any cleanup or budget pressure.
	protectedFiles := map[string]string{
		filepath.Join(workDir, "certs", "client.key"):              "private-key",
		filepath.Join(workDir, "state.yml"):                       "agent_id: x",
		filepath.Join(workDir, "policy.json"):                     "{}",
		filepath.Join(workDir, "isolation", "current.json"):        `"lease-1"`,
		filepath.Join(workDir, "upgrade", "results", "u.json"):     "{}",
		filepath.Join(workDir, "evidence-state", "pending.json"):   "{}",
		filepath.Join(workDir, "scap-state", "commands.json"):      "{}",
		filepath.Join(workDir, "windowsupdate", "state.json"):      "{}",
		filepath.Join(workDir, "cmd-dedup.json"):                   `{"schema":1,"general":[],"protected":[]}`,
		filepath.Join(workDir, "asset-sequence.json"):              `{"Agent":"a","Sequence":1}`,
		filepath.Join(queueDir, "pending.jsonl"):                   `{"reportId":"unacked"}` + "\n",
		filepath.Join(dbDir, "hashes.txt"):                         "abc Test 1\n",
		filepath.Join(qDir, "active11111111111111111111111111.meta.json"): `{"id":"active11111111111111111111111111","state":"active"}`,
		filepath.Join(qDir, "active11111111111111111111111111.payload"):   strings.Repeat("P", 4096),
		filepath.Join(qDir, "prep2222222222222222222222222222.meta.json"): `{"id":"prep2222222222222222222222222222","state":"prepared"}`,
		filepath.Join(qDir, "prep2222222222222222222222222222.payload"):   strings.Repeat("Q", 1024),
		// Terminal metadata whose payload STILL exists on disk must stay preserved.
		filepath.Join(qDir, "restoredwithpayload0000000000000.meta.json"): `{"id":"restoredwithpayload0000000000000","state":"restored"}`,
		filepath.Join(qDir, "restoredwithpayload0000000000000.payload"):   "still-here",
	}
	for p, body := range protectedFiles {
		if err := os.WriteFile(p, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		_ = os.Chtimes(p, veryOld, veryOld)
	}

	// Reclaimable stale staging temps + aged orphan deleted metadata + fresh temp (kept!).
	staleMetaTmp := filepath.Join(qDir, "abc.meta.tmp-123")
	staleCapture := filepath.Join(qDir, "abc.capture-456")
	freshCapture := filepath.Join(qDir, "fresh.capture-789")
	oldTerminalMeta := filepath.Join(qDir, "deleted0000000000000000000000000.meta.json")
	for _, f := range []struct {
		path, content string
		mtime         time.Time
	}{
		{staleMetaTmp, strings.Repeat("t", 1024), staleTime},
		{staleCapture, strings.Repeat("c", 2048), staleTime},
		{freshCapture, "in-progress-capture", now},
		{oldTerminalMeta, `{"id":"deleted0000000000000000000000000","state":"deleted"}`, veryOld},
	} {
		if err := os.WriteFile(f.path, []byte(f.content), 0600); err != nil {
			t.Fatal(err)
		}
		_ = os.Chtimes(f.path, f.mtime, f.mtime)
	}

	// Guard forensics dumps: oldest 2 should be pruned when limit is maxFiles=2.
	ev1 := filepath.Join(evDir, "ev_1.json")
	ev2 := filepath.Join(evDir, "ev_2.json")
	ev3 := filepath.Join(evDir, "ev_3.json")
	for idx, p := range []string{ev1, ev2, ev3} {
		if err := os.WriteFile(p, []byte(strings.Repeat("e", 512)), 0600); err != nil {
			t.Fatal(err)
		}
		mt := now.Add(time.Duration(idx-5) * time.Minute)
		_ = os.Chtimes(p, mt, mt)
	}

	budget := newWorkdirBudget(workDir)
	budget.evidenceMaxFiles = 2
	budget.evidenceLimit = 4096
	budget.hardLimit = 65536
	queryFreeDiskSpace = func(string) (uint64, error) { return 512 << 20, nil }

	freedBytes, freedFiles := budget.Reclaim()
	if freedFiles != 4 || freedBytes <= 0 {
		t.Fatalf("expected 4 reclaimed files (2 stale temps, 1 terminal meta, 1 oldest evidence), got files=%d bytes=%d", freedFiles, freedBytes)
	}
	for _, removed := range []string{staleMetaTmp, staleCapture, oldTerminalMeta, ev1} {
		if _, err := os.Lstat(removed); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be reclaimed", removed)
		}
	}
	if _, err := os.Stat(freshCapture); err != nil {
		t.Fatal("fresh capture temp file should not have been deleted")
	}
	if _, err := os.Stat(ev2); err != nil {
		t.Fatal("second newest evidence file should remain")
	}
	if _, err := os.Stat(ev3); err != nil {
		t.Fatal("newest evidence file should remain")
	}
	for p := range protectedFiles {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("protected path %s was deleted by cleanup: %v", p, err)
		}
	}

	usage := budget.Snapshot()
	if usage.QueueBytes == 0 || usage.QuarantineBytes == 0 || usage.StateBytes == 0 || usage.SignatureBytes == 0 || usage.EvidenceBytes == 0 || usage.ReclaimedFiles != 4 {
		t.Fatalf("unexpected usage breakdown: %+v", usage)
	}

	// Test free-space floor: 64 MiB free blocks Bulk/Standard (<128 MiB) while allowing Critical (>32 MiB).
	queryFreeDiskSpace = func(string) (uint64, error) { return 64 << 20, nil }
	budget.invalidate()
	if err := budget.CanAdmit(priorityBulk, 1024); !errors.Is(err, errInsufficientDiskSpace) {
		t.Fatalf("expected bulk rejected below 128MiB floor, got %v", err)
	}
	if err := budget.CanAdmit(priorityStandard, 1024); !errors.Is(err, errInsufficientDiskSpace) {
		t.Fatalf("expected standard rejected below 128MiB floor, got %v", err)
	}
	if err := budget.CanAdmit(priorityCritical, 1024); err != nil {
		t.Fatalf("expected critical admitted above 32MiB floor, got %v", err)
	}

	// Below 32 MiB rejects even Critical without deleting protected/queued files.
	queryFreeDiskSpace = func(string) (uint64, error) { return 16 << 20, nil }
	budget.invalidate()
	if err := budget.CanAdmit(priorityCritical, 1024); !errors.Is(err, errInsufficientDiskSpace) {
		t.Fatalf("expected critical rejected below 32MiB floor, got %v", err)
	}

	// Total workdir hard cap triggers fail-closed rejection when irreducible state exceeds hardLimit.
	queryFreeDiskSpace = func(string) (uint64, error) { return 512 << 20, nil }
	budget.hardLimit = usage.TotalBytes + 512
	budget.invalidate()
	if err := budget.CanAdmit(priorityCritical, 1024); !errors.Is(err, errWorkdirBudgetExceeded) {
		t.Fatalf("expected hard limit rejection, got %v", err)
	}
	for p := range protectedFiles {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("protected path %s deleted on budget exhaustion: %v", p, err)
		}
	}
	if budget.Snapshot().BudgetRejects == 0 {
		t.Fatal("expected BudgetRejects counter > 0")
	}
}

func TestMetricsDropCounterAndDiagnosticVisibility(t *testing.T) {
	q, err := NewOfflineQueue(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	workDir := filepath.Dir(filepath.Dir(q.path))
	budget := newWorkdirBudget(workDir)
	q.SetBudget(budget)

	c := &Client{
		state:          &State{AgentID: "diag-agent"},
		queue:          q,
		workdirBudget:  budget,
		workDir:        workDir,
		pendingReports: make(chan *pb.Report, 1),
		log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	sample := []*pb.MetricSample{{Name: "cpu_usage", Value: 0.5}}
	c.pushMetrics(sample)
	c.pushMetrics(sample)
	c.pushMetrics(sample)
	if got := c.metricsDropped.Load(); got != 2 {
		t.Fatalf("metricsDropped = %d, want 2", got)
	}

	zipBytes, err := c.diagnosticZIP("req-diag")
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range zr.File {
		if f.Name != "runtime.json" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(workDir)) {
			t.Fatal("diagnostic leaked host workDir filesystem path")
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		if doc["metricsDropped"] != float64(2) || doc["queueStats"] == nil || doc["workdirUsage"] == nil {
			t.Fatalf("missing queue/budget diagnostic fields: %+v", doc)
		}
	}
}
