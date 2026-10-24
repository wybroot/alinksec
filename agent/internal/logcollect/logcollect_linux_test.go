//go:build linux

package logcollect

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func testCollector(t *testing.T, dir string, lines *[]*pb.LogLine) *Collector {
	t.Helper()
	return New(dir, slog.New(slog.NewTextHandler(io.Discard, nil)), func(_ string, b []*pb.LogLine) bool { *lines = append(*lines, b...); return true })
}
func rawOnly(lines []*pb.LogLine) []*pb.LogLine {
	var out []*pb.LogLine
	for _, l := range lines {
		if l.Fields["record_kind"] == "raw_log" {
			out = append(out, l)
		}
	}
	return out
}
func put(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestRawLogPartialLineSurvivesRestartWithoutChangingWhitespace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	put(t, path, []byte("  用户\t登录  \r\n\npartial"))
	var got []*pb.LogLine
	c := testCollector(t, dir, &got)
	c.tailFile(path, "auth.log")
	rows := rawOnly(got)
	if len(rows) != 2 || rows[0].Content != "  用户\t登录  " || rows[1].Content != "" || rows[0].Fields["line_ending"] != "crlf" {
		t.Fatalf("raw bytes changed: %+v", rows)
	}
	var saved stateJSON
	b, _ := os.ReadFile(filepath.Join(dir, stateFile))
	if json.Unmarshal(b, &saved) != nil || string(saved.Files[path].Prefix) != "partial" {
		t.Fatal("partial cursor not persisted")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(" finished\n")
	f.Close()
	c = testCollector(t, dir, &got)
	c.tailFile(path, "auth.log")
	c.tailFile(path, "auth.log")
	rows = rawOnly(got)
	if len(rows) != 3 || rows[2].Content != "partial finished" || rows[2].Fields["timestamp_kind"] != "observed" {
		t.Fatalf("restart or EOF duplicated/dropped: %+v", rows)
	}
}
func TestRawLogCRLFSplitAcrossReadAndRestartBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name    string
		size    int
		restart bool
	}{
		{"reader-boundary", 4095, false},
		{"restart-boundary", 7, true},
		{"truncated-poll-and-restart", maxPollBytes - 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "auth.log")
			body := strings.Repeat("x", tc.size)
			data := body + "\r"
			if !tc.restart {
				data += "\n"
			}
			put(t, path, []byte(data))
			var got []*pb.LogLine
			c := testCollector(t, dir, &got)
			c.tailFile(path, "auth.log")
			if tc.restart {
				if len(rawOnly(got)) != 0 {
					t.Fatal("partial line emitted")
				}
				f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.WriteString("\n")
				closeErr := f.Close()
				if err != nil || closeErr != nil {
					t.Fatal(err, closeErr)
				}
				c = testCollector(t, dir, &got)
				c.tailFile(path, "auth.log")
			}
			rows := rawOnly(got)
			if len(rows) != 1 {
				t.Fatalf("raw row count: %d", len(rows))
			}
			row := rows[0]
			if row.Content != body[:min(len(body), maxLineBytes)] || row.Fields["line_ending"] != "crlf" || row.Fields["original_bytes"] != strconv.Itoa(tc.size) || row.Fields["truncated"] != strconv.FormatBool(tc.size > maxLineBytes) {
				t.Fatalf("split CRLF changed text or metadata: content bytes=%d fields=%v", len(row.Content), row.Fields)
			}
		})
	}
}
func TestRawLogOversizeFragmentsStayBoundedAndLabelConversions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secure")
	put(t, path, append([]byte{0xff, 0}, []byte(strings.Repeat("x", 2<<20))...))
	var got []*pb.LogLine
	c := testCollector(t, dir, &got)
	for i := 0; i < 12; i++ {
		before := c.files[path].Offset
		c.tailFile(path, "secure")
		s := c.files[path]
		if s.Offset-before > maxPollBytes+4096 || len(s.Prefix) > maxLineBytes {
			t.Fatal("unbounded read or prefix")
		}
	}
	if len(rawOnly(got)) != 0 {
		t.Fatal("incomplete line emitted")
	}
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	_, _ = f.WriteString("\n")
	f.Close()
	c.tailFile(path, "secure")
	rows := rawOnly(got)
	if len(rows) != 1 || len(rows[0].Content) > 65536 || rows[0].Fields["truncated"] != "true" || rows[0].Fields["utf8_replaced"] != "true" || rows[0].Fields["nul_escaped"] != "true" || strings.ContainsRune(rows[0].Content, 0) {
		t.Fatalf("missing conversion labels: %+v", rows)
	}
}
func TestRawLogQueueRefusalDoesNotAdvanceAndRetryKeepsEventIdentity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secure")
	put(t, path, []byte("first\nsecond\n"))
	var rejected, accepted []*pb.LogLine
	c := testCollector(t, dir, &accepted)
	fail := true
	c.send = func(_ string, b []*pb.LogLine) bool {
		if b[0].Fields["record_kind"] == "raw_log" && fail {
			rejected = b
			return false
		}
		accepted = append(accepted, b...)
		return true
	}
	c.tailFile(path, "secure")
	if c.files[path].Offset != 0 || len(rejected) != 2 {
		t.Fatal("rejected cursor advanced")
	}
	fail = false
	c.tailFile(path, "secure")
	rows := rawOnly(accepted)
	if len(rows) != 2 || rows[0].Fields["source_event_id"] != rejected[0].Fields["source_event_id"] {
		t.Fatal("retry lost identity")
	}
}
func TestNativeRawLogCollection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secure")
	put(t, path, []byte("old\n"))
	var got []*pb.LogLine
	c := testCollector(t, dir, &got)
	c.tailFile(path, "secure")
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	put(t, path, []byte("replacement larger than previous file\n"))
	c.tailFile(path, "secure")
	put(t, path, []byte("x\n"))
	c.tailFile(path, "secure")
	rows := rawOnly(got)
	if len(rows) != 3 || rows[1].Content != "replacement larger than previous file" || rows[2].Content != "x" || rows[0].Fields["source_event_id"] == rows[2].Fields["source_event_id"] {
		t.Fatal("rotation or truncate skipped")
	}
	notices := 0
	for _, l := range got {
		if l.Fields["status"] == "rotation_gap_possible" {
			notices++
		}
	}
	if notices != 2 {
		t.Fatalf("rotation gaps not disclosed: %d", notices)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	c.tailFile(link, "secure")
	if len(rawOnly(got)) != 3 {
		t.Fatal("followed symlink")
	}
	if out := os.Getenv("ALINKSEC_RAW_LOG_EVIDENCE_FILE"); out != "" {
		evidence := map[string]any{"passed": true, "platform": runtime.GOOS + "-" + runtime.GOARCH, "head": os.Getenv("GITHUB_SHA"), "observedAt": time.Now().UnixMilli(), "checks": []string{"actual_regular_file_raw_text", "native_inode_rotation_larger_replacement", "copy_truncate_new_generation", "rotation_gap_metadata", "symlink_refused"}, "lines": rows}
		b, _ := json.MarshalIndent(evidence, "", "  ")
		if err := os.MkdirAll(filepath.Dir(out), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(out, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
