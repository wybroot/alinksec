package virusscan

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func TestResourceBudgetAppliesAcrossFilesAndPreservesPartialEvidence(t *testing.T) {
	work, root := t.TempDir(), t.TempDir()
	testDB(t, work, "resource-test", strings.Repeat("0", 64))
	for _, name := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("harmless"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	e := NewEngine(work, slog.New(slog.NewTextHandler(io.Discard, nil)))
	reads := 0
	e.SetIOBudget(func(ctx context.Context, n int) error {
		if n == 64<<10 {
			reads++
		}
		return ctx.Err()
	})
	r := e.ScanCommand(context.Background(), &pb.CmdVirusScan{TaskId: "paced", Mode: pb.CmdVirusScan_CUSTOM, Paths: []string{root}, ExecutionContract: 2}, work)
	if r.Status != pb.RptVirusResult_COMPLETE || r.FilesScanned != 2 || reads < 2 {
		t.Fatalf("unpaced scan: %+v %d", r, reads)
	}
	reads = 0
	e.CheckRealtime(filepath.Join(root, "a"), work)
	if reads == 0 {
		t.Fatal("native-event realtime checks bypass shared IO governor")
	}
	e.SetIOBudget(func(context.Context, int) error { return errors.New("resource deadline") })
	r = e.ScanCommand(context.Background(), &pb.CmdVirusScan{TaskId: "interrupted", Mode: pb.CmdVirusScan_CUSTOM, Paths: []string{root}, ExecutionContract: 2}, work)
	if r.Status == pb.RptVirusResult_COMPLETE || r.FilesScanned != 0 || len(r.GetIssues()) == 0 {
		t.Fatalf("resource interruption looked clean: %+v", r)
	}
	TrimReadBuffers()
	if len(readBuffers) != 0 {
		t.Fatal("read buffers not released")
	}
}
