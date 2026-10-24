//go:build linux

package logcollect

import (
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"path/filepath"
	"strings"
	"testing"
)

func TestInvalidCursorIsBoundedAndDoesNotReplayRawFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secure")
	put(t, path, []byte("private raw\n"))
	put(t, filepath.Join(dir, stateFile), []byte(strings.Repeat("x", 129<<10)))
	var got []*pb.LogLine
	c := testCollector(t, dir, &got)
	c.tailFile(path, "secure")
	c.tailFile(path, "secure")
	if len(rawOnly(got)) != 0 || len(got) != 1 || got[0].Fields["status"] != "cursor_invalid" {
		t.Fatal("invalid state replayed data or did not surface issue")
	}
}
