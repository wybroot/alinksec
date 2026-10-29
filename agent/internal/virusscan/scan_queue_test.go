package virusscan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/clamav"
	"github.com/alinksec/alinksec-agent/internal/clamav/clamavtest"
	"github.com/alinksec/alinksec-agent/internal/configguard"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/yara"
	"github.com/alinksec/alinksec-agent/internal/yara/yaratest"
	"google.golang.org/protobuf/proto"
)

func waitForQueuedScan(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	buf := make([]byte, 1<<20)
	for time.Now().Before(deadline) {
		n := runtime.Stack(buf, true)
		for _, stack := range strings.Split(string(buf[:n]), "\n\n") {
			if strings.Contains(stack, "virusscan.(*Engine).ScanCommand(") &&
				(strings.Contains(stack, "sync.(*Mutex).Lock(") || strings.Contains(stack, "[select]")) {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("scan did not queue behind the active task")
}

func TestQueuedScanCancellationStopsBeforeDispatchAndRecovers(t *testing.T) {
	for _, selected := range []string{"builtin", "yara", "clamav"} {
		for _, timing := range []string{"already-canceled", "cancel-queued", "parent-deadline", "task-deadline"} {
			t.Run(selected+"/"+timing, func(t *testing.T) {
				work, root := t.TempDir(), t.TempDir()
				data := []byte("harmless queued task marker")
				digest := fmt.Sprintf("%x", sha256.Sum256(data))
				paths := []string{filepath.Join(root, "active.txt"), filepath.Join(root, "queued.txt")}
				for _, path := range paths {
					if err := os.WriteFile(path, data, 0600); err != nil {
						t.Fatal(err)
					}
				}
				engine := NewEngine(work, quietLogger())
				version, contract := "queued-fixture", uint32(2)
				var yc *yara.Client
				var cc *clamav.Client
				var streams atomic.Int64
				switch selected {
				case "builtin":
					testDB(t, work, version, digest)
				case "yara":
					_, _ = yaratest.Native(t)
					const rules = `rule QueuedTaskMarker { strings: $s="harmless queued task marker" condition: $s }`
					yc = yara.New(yaratest.Config(t, rules), configguard.ReadFile)
					engine.SetYARA(yc)
					version = fmt.Sprintf("YARA 4.5.8/sha256:%x", sha256.Sum256([]byte(rules)))
					contract = 4
				case "clamav":
					cc = clamav.New(clamavtest.Start(t, func(conn net.Conn) {
						command, err := clamavtest.Command(conn)
						if err != nil {
							return
						}
						if command == "zVERSION\x00" {
							clamavtest.Reply(conn, clamVersion)
							return
						}
						if command != "zINSTREAM\x00" {
							t.Error("unexpected daemon command", command)
							return
						}
						streams.Add(1)
						input, err := clamavtest.Stream(conn)
						if err != nil || !bytes.Equal(input, data) {
							t.Error("daemon received unexpected input", err)
							return
						}
						clamavtest.Reply(conn, "stream: Harmless.Queued FOUND")
					}))
					engine.SetClamAV(cc)
					version, contract = clamVersion, 3
				}
				entered, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				defer unblock()
				var blocked atomic.Bool
				engine.SetIOBudget(func(ctx context.Context, _ int) error {
					if blocked.CompareAndSwap(false, true) {
						close(entered)
						select {
						case <-release:
						case <-ctx.Done():
						}
					}
					return ctx.Err()
				})
				command := &pb.CmdVirusScan{TaskId: "active", Mode: pb.CmdVirusScan_CUSTOM, Paths: paths[:1], Engine: selected, ExecutionContract: contract, ExpectedDbVersion: version, TimeLimitSec: 5}
				active := make(chan *pb.RptVirusResult, 1)
				go func() { active <- engine.ScanCommand(context.Background(), command, work) }()
				select {
				case <-entered:
				case <-time.After(3 * time.Second):
					t.Fatal("active scan did not reach its dispatch barrier")
				}
				parent, cancel := context.WithCancel(context.Background())
				if timing == "parent-deadline" {
					cancel()
					parent, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
				}
				defer cancel()
				queuedCommand := proto.Clone(command).(*pb.CmdVirusScan)
				queuedCommand.TaskId, queuedCommand.Paths = "queued", paths[1:]
				if timing == "task-deadline" {
					queuedCommand.TimeLimitSec = 1
				}
				if timing == "already-canceled" {
					cancel()
				}
				queued := make(chan *pb.RptVirusResult, 1)
				started := time.Now()
				go func() { queued <- engine.ScanCommand(parent, queuedCommand, work) }()
				if timing == "cancel-queued" {
					waitForQueuedScan(t)
					cancel()
				}
				var result *pb.RptVirusResult
				select {
				case result = <-queued:
				case <-time.After(1800 * time.Millisecond):
					unblock()
					<-active
					<-queued
					t.Fatal("canceled or expired task waited for the active scan to release its lock")
				}
				if elapsed := time.Since(started); timing == "task-deadline" && (elapsed < 800*time.Millisecond || result.DurationMs < 800) {
					t.Fatal("task deadline did not include the real queue wait", elapsed, result)
				}
				if result.TaskId != "queued" || result.Status != pb.RptVirusResult_FAILED || !result.BudgetExhausted || result.ExecutionContract != contract || result.ScanEngine != selected || result.DbVersion != "" || result.Coverage == "" || result.FilesSeen != 0 || result.FilesScanned != 0 || result.FilesFailed != 0 || result.FilesSkipped != 0 || result.BytesRead != 0 || len(result.Findings) != 0 || len(result.Issues) != 1 || result.Issues[0].Path != "" || result.Issues[0].Code != "budget_exhausted" {
					t.Fatal("unstarted task claimed input, versions, coverage or file failure", result)
				}
				if yc != nil && yc.Status().Scans != 0 || cc != nil && cc.Status().Scans != 0 || streams.Load() != 0 {
					t.Fatal("queued task dispatched an external file scan")
				}
				if got, err := os.ReadFile(paths[1]); err != nil || !bytes.Equal(got, data) {
					t.Fatal("unstarted task changed its file", err)
				}
				historical := proto.Clone(result)
				unblock()
				first := <-active
				queuedCommand.TaskId, queuedCommand.TimeLimitSec = "recovered", 5
				fresh := engine.ScanCommand(context.Background(), queuedCommand, work)
				for _, report := range []*pb.RptVirusResult{first, fresh} {
					if report.Status != pb.RptVirusResult_COMPLETE || report.DbVersion != version || report.FilesScanned != 1 || report.FilesFailed != 0 || report.BytesRead != uint64(len(data)) || len(report.Findings) != 1 || report.BudgetExhausted {
						t.Fatal("active or subsequent task did not complete", report)
					}
					finding := report.Findings[0]
					if finding.ActionTaken != "quarantined" || finding.Sha256 != digest || finding.QuarantineId == "" || finding.ActionError != "" {
						t.Fatal("task lost disposition identity", finding)
					}
					if err := NewQuarantine(work).RestoreExpected(context.Background(), finding.Path, finding.QuarantineId, digest); err != nil {
						t.Fatal(err)
					}
					if got, err := os.ReadFile(finding.Path); err != nil || !bytes.Equal(got, data) {
						t.Fatal("recovery changed original bytes", err)
					}
				}
				if !proto.Equal(result, historical) {
					t.Fatal("later tasks rewrote the queued failure")
				}
				if yc != nil && (yc.Status().Scans != 2 || yc.Status().Failures != 0) || cc != nil && (cc.Status().Scans != 2 || cc.Status().Failures != 0) || cc != nil && streams.Load() != 2 {
					t.Fatal("unstarted task polluted external attempt or failure counts")
				}
			})
		}
	}
}

func TestScanDeadlineIncludesWaitForEngineLock(t *testing.T) {
	work := t.TempDir()
	path := filepath.Join(t.TempDir(), "harmless.txt")
	if err := os.WriteFile(path, []byte("harmless queue budget fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	testDB(t, work, "queue-budget", strings.Repeat("0", 64))
	engine := NewEngine(work, quietLogger())
	var remaining time.Duration
	engine.SetIOBudget(func(ctx context.Context, _ int) error {
		deadline, _ := ctx.Deadline()
		remaining = time.Until(deadline)
		<-ctx.Done()
		return ctx.Err()
	})
	engine.mu.Lock()
	command := &pb.CmdVirusScan{TaskId: "queue-budget", Mode: pb.CmdVirusScan_CUSTOM, Paths: []string{path}, ExecutionContract: 2, TimeLimitSec: 1}
	result := make(chan *pb.RptVirusResult, 1)
	started := time.Now()
	go func() { result <- engine.ScanCommand(context.Background(), command, work) }()
	waitForQueuedScan(t)
	// Allow dispatch before expiry, then observe the actual remaining context
	// inside the production IO callback. The wait must not reset the deadline.
	time.Sleep(600 * time.Millisecond)
	engine.mu.Unlock()
	report := <-result
	if elapsed := time.Since(started); elapsed > 1400*time.Millisecond || remaining > 600*time.Millisecond || remaining <= 0 {
		t.Fatal("queue wait was excluded from the task deadline", elapsed, remaining, report)
	}
	if report.Status != pb.RptVirusResult_FAILED || !report.BudgetExhausted || report.FilesSeen != 0 || report.BytesRead != 0 || len(report.Findings) != 0 || report.DurationMs < 800 {
		t.Fatal("expired dispatch misreported completion or its total duration", report)
	}
}
