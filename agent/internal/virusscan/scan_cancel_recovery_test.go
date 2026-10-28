package virusscan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
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

const taskCancelRules = `rule TaskCancelMarker { strings: $s="harmless task cancel marker" condition: $s }`

func TestBuiltinTaskCancellationPreservesEvidenceAndRecovers(t *testing.T) {
	for _, timing := range []string{"between-files", "partial-input", "task-deadline"} {
		t.Run(timing, func(t *testing.T) { runTaskCancellationRecovery(t, "builtin", timing) })
	}
}

func TestNativeYARATaskCancellationPreservesEvidenceAndRecovers(t *testing.T) {
	_, _ = yaratest.Native(t)
	for _, timing := range []string{"between-files", "partial-input", "task-deadline"} {
		t.Run(timing, func(t *testing.T) { runTaskCancellationRecovery(t, "yara", timing) })
	}
}

func TestClamavTaskCancellationPreservesEvidenceAndRecovers(t *testing.T) {
	for _, timing := range []string{"between-files", "partial-input", "task-deadline", "waiting-for-verdict"} {
		t.Run(timing, func(t *testing.T) { runTaskCancellationRecovery(t, "clamav", timing) })
	}
}

func runTaskCancellationRecovery(t *testing.T, selected, timing string) {
	t.Helper()
	work, root := t.TempDir(), t.TempDir()
	data := append([]byte("harmless task cancel marker"), bytes.Repeat([]byte("_"), (64<<10)+17-len("harmless task cancel marker"))...)
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	paths := make([]string, 3)
	for i := range paths {
		paths[i] = filepath.Join(root, fmt.Sprintf("marker-%d", i))
		if err := os.WriteFile(paths[i], data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	original, err := os.Stat(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine := NewEngine(work, quietLogger())
	version, name, findingEngine, contract := "cancel-fixture", "Test.Harmless", "hash", uint32(2)
	var yc *yara.Client
	var cc *clamav.Client
	var streams, completeStreams atomic.Int64
	connectionClosed := make(chan error, 1)
	streamDone := make(chan struct{}, 8)
	switch selected {
	case "builtin":
		testDB(t, work, version, digest)
	case "yara":
		yc = yara.New(yaratest.Config(t, taskCancelRules), configguard.ReadFile)
		engine.SetYARA(yc)
		version = fmt.Sprintf("YARA 4.5.8/sha256:%x", sha256.Sum256([]byte(taskCancelRules)))
		name, findingEngine, contract = "TaskCancelMarker", "yara", 4
	case "clamav":
		cfg := clamavtest.Start(t, func(conn net.Conn) {
			command, err := clamavtest.Command(conn)
			if err != nil {
				return
			}
			if command == "zVERSION\x00" {
				clamavtest.Reply(conn, clamVersion)
				return
			}
			if command != "zINSTREAM\x00" {
				t.Error("unexpected protocol command", command)
				return
			}
			attempt := streams.Add(1)
			defer func() { streamDone <- struct{}{} }()
			input, err := clamavtest.Stream(conn)
			if err != nil {
				return
			}
			completeStreams.Add(1)
			if !bytes.Equal(input, data) {
				t.Error("daemon received different complete input")
				return
			}
			if timing == "waiting-for-verdict" && attempt == 2 {
				cancel()
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				var b [1]byte
				_, err := conn.Read(b[:])
				connectionClosed <- err
				return
			}
			clamavtest.Reply(conn, "stream: Harmless.Cancel FOUND")
		})
		cc = clamav.New(cfg)
		engine.SetClamAV(cc)
		version, name, findingEngine, contract = clamVersion, "Harmless.Cancel", "clamav", 3
	default:
		t.Fatal("unknown engine", selected)
	}
	visits := 0
	var interruption error
	engine.SetIOBudget(func(ctx context.Context, n int) error {
		if n == 4096 {
			visits++
			if visits == 2 && timing == "between-files" {
				cancel()
				interruption = ctx.Err()
				return interruption
			}
		}
		// All samples need a full first chunk and a short tail. Stop before
		// reading the second file's tail, after exactly 64 KiB of its input.
		if visits == 2 && n == 17 {
			switch timing {
			case "partial-input":
				cancel()
			case "task-deadline":
				<-ctx.Done()
			default:
				return nil
			}
			interruption = ctx.Err()
			return interruption
		}
		return ctx.Err()
	})
	command := &pb.CmdVirusScan{TaskId: "interrupted-task", Mode: pb.CmdVirusScan_CUSTOM, Paths: paths, Engine: selected, ExecutionContract: contract, ExpectedDbVersion: version, TimeLimitSec: 5}
	if timing == "task-deadline" {
		command.TimeLimitSec = 1
	}
	started := time.Now()
	result := engine.ScanCommand(parent, command, work)
	if elapsed := time.Since(started); elapsed > 4*time.Second || timing == "task-deadline" && elapsed < 800*time.Millisecond {
		t.Fatal("task did not respect its cancellation or real deadline", elapsed, result)
	}
	if timing == "waiting-for-verdict" {
		select {
		case err := <-connectionClosed:
			if !errors.Is(err, io.EOF) {
				t.Fatal("cancellation did not close the pending daemon connection", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("pending daemon connection outlived cancellation")
		}
	} else {
		expected := error(context.Canceled)
		if timing == "task-deadline" {
			expected = context.DeadlineExceeded
		}
		if !errors.Is(interruption, expected) {
			t.Fatal("fixture failed to interrupt the task at the intended boundary", interruption)
		}
	}
	seen, failed, expectedBytes := uint32(2), uint32(1), uint64(len(data)+(64<<10))
	fileIssue := "budget_exhausted"
	if selected != "builtin" {
		fileIssue = selected + "_timeout"
	}
	if timing == "between-files" {
		seen, failed, expectedBytes = 1, 0, uint64(len(data))
	} else if timing == "waiting-for-verdict" {
		expectedBytes = uint64(2 * len(data))
	}
	if result.Status != pb.RptVirusResult_PARTIAL || result.ScanEngine != selected || result.ExecutionContract != contract || result.DbVersion != version || result.FilesSeen != seen || result.FilesScanned != 1 || result.FilesFailed != failed || result.FilesSkipped != 0 || result.BytesRead != expectedBytes || !result.BudgetExhausted || len(result.Findings) != 1 || len(result.Issues) != int(failed)+1 || visits != 2 {
		t.Fatal("interrupted task lost coverage, byte counts or completed findings", result, visits)
	}
	if failed != 0 && (result.Issues[0].Path != paths[1] || result.Issues[0].Code != fileIssue) {
		t.Fatal("interrupted input lost its per-file failure", result.Issues)
	}
	last := result.Issues[len(result.Issues)-1]
	if last.Path != "" || last.Code != "budget_exhausted" {
		t.Fatal("unvisited remainder was reported as complete", result.Issues)
	}
	for _, path := range paths[1:] {
		if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, data) {
			t.Fatal("canceled task changed an incomplete or unvisited file", path, err)
		}
	}
	checkCounters := func(scans uint64) {
		t.Helper()
		if yc != nil {
			status := yc.Status()
			if status.Scans != scans || status.Failures != uint64(failed) || status.ScanFailures.Counts["yara_timeout"] != uint64(failed) {
				t.Fatal("YARA lost cumulative canceled-attempt accounting", status)
			}
		}
		if cc != nil {
			status := cc.Status()
			if status.Scans != scans || status.Failures != uint64(failed) {
				t.Fatal("ClamAV lost cumulative canceled-attempt accounting", status)
			}
		}
	}
	checkCounters(uint64(seen))
	oldStreams, oldComplete := int64(seen), int64(1)
	if timing == "waiting-for-verdict" {
		oldComplete = 2
	}
	waitStreams := func(count int64) {
		t.Helper()
		if cc == nil {
			return
		}
		for i := int64(0); i < count; i++ {
			select {
			case <-streamDone:
			case <-time.After(2 * time.Second):
				t.Fatal("daemon stream handler did not finish after its task")
			}
		}
	}
	waitStreams(oldStreams)
	if cc != nil && (streams.Load() != oldStreams || completeStreams.Load() != oldComplete) {
		t.Fatal("canceled task sent an unexpected daemon input", streams.Load(), completeStreams.Load())
	}
	restore := func(r *pb.RptVirusResult) {
		t.Helper()
		findingVersion := version
		if selected == "builtin" {
			// Builtin findings carry the hash identity; the task reports its
			// database version separately in RptVirusResult.DbVersion.
			findingVersion = ""
		}
		for _, f := range r.Findings {
			if f.Engine != findingEngine || f.EngineVersion != findingVersion || f.Name != name || f.Sha256 != digest || f.Size != uint64(len(data)) || f.ActionTaken != "quarantined" || f.ActionError != "" || f.QuarantineId == "" {
				t.Fatal("finding lost engine, file or disposition evidence", f)
			}
			if selected == "yara" && (len(f.MatchedRules) != 1 || f.MatchedRules[0] != name) {
				t.Fatal("finding lost the exact native rule identifier", f)
			}
			if _, err := os.Lstat(f.Path); !os.IsNotExist(err) {
				t.Fatal("quarantined path still exists", f.Path, err)
			}
			if err := NewQuarantine(work).RestoreExpected(context.Background(), f.Path, f.QuarantineId, digest); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(f.Path)
			st, statErr := os.Stat(f.Path)
			if err != nil || statErr != nil || !bytes.Equal(got, data) || st.Mode().Perm() != original.Mode().Perm() {
				t.Fatal("restore changed detected bytes or permissions", err, statErr)
			}
		}
	}
	if result.Findings[0].Path != paths[0] {
		t.Fatal("task retained a finding for the wrong file", result)
	}
	historical := proto.Clone(result)
	restore(result)
	command.TaskId, command.TimeLimitSec = "recovered-task", 5
	fresh := engine.ScanCommand(context.Background(), command, work)
	if fresh.Status != pb.RptVirusResult_COMPLETE || fresh.ScanEngine != selected || fresh.DbVersion != version || fresh.ExecutionContract != contract || fresh.FilesSeen != 3 || fresh.FilesScanned != 3 || fresh.FilesFailed != 0 || fresh.FilesSkipped != 0 || fresh.BytesRead != uint64(3*len(data)) || fresh.BudgetExhausted || len(fresh.Findings) != 3 || len(fresh.Issues) != 0 {
		t.Fatal("task or engine gate did not recover after cancellation", fresh)
	}
	for i, f := range fresh.Findings {
		if f.Path != paths[i] || i == 0 && f.QuarantineId == result.Findings[0].QuarantineId {
			t.Fatal("fresh task reused prior file or quarantine evidence", fresh)
		}
	}
	restore(fresh)
	checkCounters(uint64(seen) + 3)
	if !proto.Equal(result, historical) {
		t.Fatal("recovery rewrote the interrupted task's historical evidence", result)
	}
	waitStreams(3)
	if cc != nil && (streams.Load() != oldStreams+3 || completeStreams.Load() != oldComplete+3) {
		t.Fatal("fresh daemon scans did not recover exactly three inputs", streams.Load(), completeStreams.Load())
	}
}
