package yara

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

func TestQueuedScanTimeoutIsCountedWithoutReadingFile(t *testing.T) {
	c := New(Config{}, nil)
	c.gate <- struct{}{}
	defer func() { <-c.gate }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := c.Scan(ctx, "", nil)
	s := c.Status()
	if Code(err) != "yara_timeout" || s.Scans != 1 || s.Failures != 1 || s.ScanFailures.Counts["yara_timeout"] != 1 || s.ScanFailures.LastAt != s.LastScanAt || s.ScanFailures.LastIssue != "yara_timeout" {
		t.Fatalf("err=%v status=%+v", err, s)
	}
	// Callers cannot mutate live counters through a status snapshot.
	s.ScanFailures.Counts["yara_timeout"] = 123
	if c.Status().ScanFailures.Counts["yara_timeout"] != 1 {
		t.Fatal("status exposes mutable counters")
	}
}

func TestFailureTelemetryFitsExistingHeartbeatLimit(t *testing.T) {
	c := New(Config{}, nil)
	c.status.State = "ready"
	c.status.Version = "YARA 4.5.8/sha256:" + strings.Repeat("a", 64)
	c.status.LastIssue = "yara_read_failed_or_changed"
	c.status.LastScanAt = 4102444800
	c.status.ObservedAt = 4102444800
	c.status.ScanFailures.LastAt = 4102444800
	c.status.ScanFailures.LastIssue = c.status.LastIssue
	codes := strings.Fields("yara_disabled yara_not_built yara_invalid_config yara_timeout yara_rules_unavailable yara_rules_changed yara_version_changed yara_worker_failed yara_worker_protocol yara_resource_limit yara_compile_error yara_empty_rules yara_rule_limit yara_match_limit yara_file_limit yara_scan_error yara_read_failed_or_changed")
	for _, code := range codes {
		c.status.ScanFailures.Counts[code] = math.MaxInt64 / uint64(len(codes))
		c.status.Failures += c.status.ScanFailures.Counts[code]
	}
	c.status.Scans = math.MaxInt64
	c.status.Update = UpdateStatus{Enabled: true, LastIssue: "yara_read_failed_or_changed", CheckedAt: 4102444800, SuccessAt: 4102444800, ChangedAt: 4102444800, NextCheckAt: 4102444800}
	b, err := json.Marshal(c.Status())
	if err != nil || len(b) > 2048 {
		t.Fatalf("heartbeat bytes=%d err=%v", len(b), err)
	}
	t.Logf("maximum failure metadata heartbeat: %d bytes", len(b))
}
