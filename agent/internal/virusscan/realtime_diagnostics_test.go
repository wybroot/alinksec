package virusscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type closedSnapshotSink struct{}

func (closedSnapshotSink) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestSnapshotDiagnosticsRejectChangedAndOversizedFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ordinary.txt")
	if err := os.WriteFile(path, []byte("ordinary"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), ioBudgetKey{}, func(context.Context, int) error {
		return os.WriteFile(path, []byte("changed while being read"), 0600)
	})
	s, err := readSnapshotScopedSink(ctx, path, 128, 128, false, "", "", io.Discard)
	if s.sum != "" || snapshotIssueCode(ctx, err) != "file_changed" {
		t.Fatalf("changed file accepted: snapshot=%+v err=%v", s, err)
	}
	s, err = readSnapshot(context.Background(), path, 1, 128, false)
	if s.sum != "" || s.bytesRead != 0 || snapshotIssueCode(context.Background(), err) != "file_limit" {
		t.Fatalf("oversize file read: snapshot=%+v err=%v", s, err)
	}
	s, err = readSnapshotScopedSink(context.Background(), path, 128, 128, false, "", "", closedSnapshotSink{})
	if s.sum != "" || snapshotIssueCode(context.Background(), err) != "stream_failed" || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("pipe failure confused with file read: snapshot=%+v err=%v", s, err)
	}
}

func TestRealtimeDiagnosticsBoundChurnAndKeepOnlyRepresentativePathsInLog(t *testing.T) {
	var logs bytes.Buffer
	e := &Engine{log: slog.New(slog.NewJSONHandler(&logs, nil))}
	for n := 0; n < 1000; n++ {
		e.realtimeFailure("yara", "scan", filepath.Join("/tmp", time.Unix(int64(n), 0).Format(time.RFC3339)), snapshot{}, 0, time.Now(), context.Background(), os.ErrNotExist, os.ErrNotExist)
	}
	if len(e.realtimeIssues) != 1 || bytes.Count(logs.Bytes(), []byte("\n")) != 1 {
		t.Fatalf("unbounded diagnostics: categories=%d logs=%s", len(e.realtimeIssues), logs.String())
	}
	key := realtimeIssueKey{"yara", "input", "file_missing"}
	w := e.realtimeIssues[key]
	if w.suppressed != 999 {
		t.Fatal("churn not counted", w)
	}
	w.at = time.Now().Add(-time.Minute)
	e.realtimeIssues[key] = w
	e.realtimeFailure("yara", "scan", "/tmp/latest", snapshot{}, 0, time.Now(), context.Background(), os.ErrNotExist, os.ErrNotExist)
	decoder := json.NewDecoder(&logs)
	var first, next map[string]any
	if decoder.Decode(&first) != nil || decoder.Decode(&next) != nil || next["suppressed"] != float64(999) || next["path"] != "/tmp/latest" || next["reason"] != "file_missing" || next["phase"] != "input" {
		t.Fatalf("missing bounded summary: first=%v next=%v", first, next)
	}
}
