package virusscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/alinksec/alinksec-agent/internal/clamav"
	"github.com/alinksec/alinksec-agent/internal/clamav/clamavtest"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

const clamVersion = "ClamAV 1.4.6/fixture"

func clamEngine(t *testing.T, response string, beforeReply func()) (*Engine, string) {
	work := t.TempDir()
	cfg := clamavtest.Start(t, func(c net.Conn) {
		cmd, _ := clamavtest.Command(c)
		if cmd == "zVERSION\x00" {
			clamavtest.Reply(c, clamVersion)
			return
		}
		if cmd == "zINSTREAM\x00" {
			_, err := clamavtest.Stream(c)
			if err != nil {
				return
			}
			if beforeReply != nil {
				beforeReply()
			}
			clamavtest.Reply(c, response)
		}
	})
	e := NewEngine(work, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.SetClamAV(clamav.New(cfg))
	return e, work
}
func clamCommand(path string) *pb.CmdVirusScan {
	return &pb.CmdVirusScan{TaskId: "1", Mode: pb.CmdVirusScan_CUSTOM, Paths: []string{path}, ExecutionContract: 3, Engine: "clamav", ExpectedDbVersion: clamVersion}
}
func TestClamavIndependentDatabaseAndByteBoundQuarantine(t *testing.T) {
	e, work := clamEngine(t, "stream: Harmless.Marker FOUND", nil)
	path := filepath.Join(t.TempDir(), "marker.txt")
	data := []byte("harmless ClamAV engine fixture")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	r := e.ScanCommand(context.Background(), clamCommand(path), work)
	if r.GetStatus() != pb.RptVirusResult_COMPLETE || r.GetScanEngine() != "clamav" || r.GetExecutionContract() != 3 || len(r.Findings) != 1 {
		t.Fatalf("result=%+v", r)
	}
	f := r.Findings[0]
	sum := sha256.Sum256(data)
	if f.Engine != "clamav" || f.EngineVersion != clamVersion || f.Sha256 != hex.EncodeToString(sum[:]) || f.ActionTaken != "quarantined" || f.QuarantineId == "" {
		t.Fatalf("finding=%+v", f)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("quarantine source=%v", err)
	}
	if err := NewQuarantine(work).RestoreExpected(context.Background(), path, f.QuarantineId, f.Sha256); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(data) {
		t.Fatalf("restore=%q err=%v", got, err)
	}
}
func TestClamavFailureAndOldContractNeverQuarantine(t *testing.T) {
	for _, response := range []string{"stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND", "stream: Heuristics.Encrypted.Zip FOUND", "stream: malformed", "stream: ERROR"} {
		t.Run(response, func(t *testing.T) {
			e, work := clamEngine(t, response, nil)
			path := filepath.Join(t.TempDir(), "marker")
			os.WriteFile(path, []byte("harmless"), 0600)
			cmd := clamCommand(path)
			cmd.ExecutionContract = 2
			if r := e.ScanCommand(context.Background(), cmd, work); r.GetStatus() != pb.RptVirusResult_FAILED || len(r.Findings) != 0 {
				t.Fatal(r)
			}
			cmd.ExecutionContract = 3
			r := e.ScanCommand(context.Background(), cmd, work)
			if r.GetStatus() != pb.RptVirusResult_FAILED || r.FilesFailed != 1 || len(r.Findings) != 0 {
				t.Fatal(r)
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestClamavRechecksBytesAfterDaemonVerdict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "marker")
	os.WriteFile(path, []byte("original marker"), 0600)
	e, work := clamEngine(t, "stream: Harmless.Marker FOUND", func() {
		if err := os.WriteFile(path, []byte("different bytes"), 0600); err != nil {
			panic(err)
		}
	})
	r := e.ScanCommand(context.Background(), clamCommand(path), work)
	if len(r.Findings) != 1 || r.Findings[0].ActionTaken != "alert_only" || r.Findings[0].ActionError == "" {
		t.Fatal(r)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "different bytes" {
		t.Fatalf("replacement=%q err=%v", b, err)
	}
}
func TestClamavWhitelistRealtimeAndOversize(t *testing.T) {
	e, work := clamEngine(t, "stream: Harmless.Marker FOUND", nil)
	path := filepath.Join(t.TempDir(), "marker")
	data := []byte("harmless")
	os.WriteFile(path, data, 0600)
	sum := sha256.Sum256(data)
	e.policyReader = func() ([]byte, error) {
		return []byte(`{"virus_whitelist":[{"type":"hash","value":"` + hex.EncodeToString(sum[:]) + `"}],"virus_realtime":{"enabled":true,"action":"alert_only"}}`), nil
	}
	if f := e.CheckRealtime(path, work); f != nil {
		t.Fatal(f)
	}
	if r := e.ScanCommand(context.Background(), clamCommand(path), work); len(r.Findings) != 0 || r.Status != pb.RptVirusResult_COMPLETE {
		t.Fatal(r)
	}
	e.policyReader = func() ([]byte, error) {
		return []byte(`{"virus_realtime":{"enabled":true,"action":"alert_only"}}`), nil
	}
	if f := e.CheckRealtime(path, work); f == nil || f.Engine != "clamav" || f.ActionTaken != "alert_only" {
		t.Fatal(f)
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	err = f.Truncate(clamav.MaxFileBytes + 1)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	r := e.ScanCommand(context.Background(), clamCommand(path), work)
	if r.Status != pb.RptVirusResult_FAILED || len(r.Findings) != 0 || !strings.Contains(r.String(), "clamav_file_limit") {
		t.Fatal(r)
	}
}

func TestClamavFileTimeoutDoesNotConsumeWholeTaskDeadline(t *testing.T) {
	e, work := clamEngine(t, "stream: OK", nil)
	root := t.TempDir()
	paths := []string{filepath.Join(root, "first"), filepath.Join(root, "second")}
	for _, p := range paths {
		if err := os.WriteFile(p, []byte("harmless"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var blocked atomic.Bool
	e.SetIOBudget(func(ctx context.Context, n int) error {
		if n == len("harmless") && blocked.CompareAndSwap(false, true) {
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	})
	cmd := clamCommand(paths[0])
	cmd.Paths = paths
	r := e.ScanCommand(context.Background(), cmd, work)
	if r.Status != pb.RptVirusResult_PARTIAL || r.FilesFailed != 1 || r.FilesScanned != 1 || r.BudgetExhausted || len(r.Findings) != 0 || !strings.Contains(r.String(), "clamav_timeout") {
		t.Fatalf("file timeout stopped remaining work: %+v", r)
	}
}
