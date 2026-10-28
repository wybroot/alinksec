package virusscan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/alinksec/alinksec-agent/internal/clamav"
	"github.com/alinksec/alinksec-agent/internal/clamav/clamavtest"
	"github.com/alinksec/alinksec-agent/internal/configguard"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/yara"
	"github.com/alinksec/alinksec-agent/internal/yara/yaratest"
	"google.golang.org/protobuf/proto"
)

const taskBeforeRules = `rule BeforeTaskUpdate { strings: $s="harmless before task update" condition: $s }`
const taskAfterRules = `rule AfterTaskUpdate { strings: $s="harmless after task update" condition: $s }`

func updateBoundaryFiles(t *testing.T) ([]string, map[string][]byte) {
	t.Helper()
	root := t.TempDir()
	paths := make([]string, 3)
	contents := make(map[string][]byte)
	for i := range paths {
		paths[i] = filepath.Join(root, fmt.Sprintf("marker-%d", i))
		contents[paths[i]] = []byte(fmt.Sprintf("harmless before task update; harmless after task update; file %d", i))
		if err := os.WriteFile(paths[i], contents[paths[i]], 0600); err != nil {
			t.Fatal(err)
		}
	}
	return paths, contents
}

func checkBoundaryTask(t *testing.T, result *pb.RptVirusResult, engine, version, code string, scanned int, expectedBytes uint64) {
	t.Helper()
	status := pb.RptVirusResult_COMPLETE
	if scanned == 0 {
		status = pb.RptVirusResult_FAILED
	} else if scanned < 3 {
		status = pb.RptVirusResult_PARTIAL
	}
	contract := uint32(3)
	if engine == "yara" {
		contract = 4
	}
	if result.Status != status || result.ScanEngine != engine || result.DbVersion != version || result.ExecutionContract != contract || result.FilesSeen != 3 || result.FilesScanned != uint32(scanned) || result.FilesFailed != uint32(3-scanned) || result.FilesSkipped != 0 || result.BytesRead != expectedBytes || result.BudgetExhausted || len(result.Findings) != scanned || len(result.Issues) != 3-scanned {
		t.Fatal("task lost its pinned version, partial results or exact coverage accounting", result)
	}
	seen := map[string]bool{}
	for _, issue := range result.Issues {
		if issue.Code != code || issue.Path == "" || seen[issue.Path] {
			t.Fatal("version failure lost per-file evidence", result.Issues)
		}
		seen[issue.Path] = true
	}
}

func restoreBoundaryFindings(t *testing.T, work string, result *pb.RptVirusResult, name string, contents map[string][]byte) {
	t.Helper()
	for _, finding := range result.Findings {
		content, ok := contents[finding.Path]
		if !ok || finding.Engine != result.ScanEngine || finding.EngineVersion != result.DbVersion || finding.Name != name || finding.Sha256 != fmt.Sprintf("%x", sha256.Sum256(content)) || finding.Size != uint64(len(content)) || finding.ActionTaken != "quarantined" || finding.QuarantineId == "" || finding.ActionError != "" {
			t.Fatal("finding mixed task, engine, file or disposition evidence", finding)
		}
		if result.ScanEngine == "yara" && (len(finding.MatchedRules) != 1 || finding.MatchedRules[0] != name) {
			t.Fatal("finding lost the exact native rule identifier", finding)
		}
		if _, err := os.Lstat(finding.Path); !os.IsNotExist(err) {
			t.Fatal("quarantined path still exists", finding.Path, err)
		}
		if err := NewQuarantine(work).RestoreExpected(context.Background(), finding.Path, finding.QuarantineId, finding.Sha256); err != nil {
			t.Fatal(err)
		}
		if restored, err := os.ReadFile(finding.Path); err != nil || !bytes.Equal(restored, content) {
			t.Fatal("restore did not preserve the detected bytes", finding.Path, err)
		}
	}
}

func TestNativeYARATaskPinsVersionAcrossApprovedUpdate(t *testing.T) {
	_, _ = yaratest.Native(t)
	for _, fault := range []struct{ name, source, code string }{
		{"success", taskAfterRules, ""},
		{"download", "publisher unavailable", "yara_update_download"},
		{"compile", "rule Broken { condition: }", "yara_compile_error"},
	} {
		t.Run(fault.name, func(t *testing.T) {
			var mu sync.Mutex
			source, status := taskBeforeRules, http.StatusOK
			publish := func(rules string, code int) {
				mu.Lock()
				defer mu.Unlock()
				source, status = rules, code
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				w.WriteHeader(status)
				_, _ = io.WriteString(w, source)
			}))
			t.Cleanup(server.Close)
			ca := filepath.Join(t.TempDir(), "publisher-ca.crt")
			if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			work := t.TempDir()
			client := yara.NewWithUpdates(yara.Config{Enabled: true, UpdateURL: server.URL + "/approved.yar", UpdateCAFile: ca, TimeoutSec: 10}, configguard.ReadFile, work)
			if err := client.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			oldVersion := fmt.Sprintf("YARA 4.5.8/sha256:%x", sha256.Sum256([]byte(taskBeforeRules)))
			newVersion := fmt.Sprintf("YARA 4.5.8/sha256:%x", sha256.Sum256([]byte(taskAfterRules)))
			paths, contents := updateBoundaryFiles(t)
			engine := NewEngine(work, quietLogger())
			engine.SetYARA(client)
			visits := 0
			var updateErr error
			engine.SetIOBudget(func(ctx context.Context, n int) error {
				if n != 4096 {
					return nil
				}
				visits++
				if visits == 2 {
					code := http.StatusOK
					if fault.name == "download" {
						code = http.StatusServiceUnavailable
					}
					publish(fault.source, code)
					// The first file has released the native scan gate. Commit an
					// actual approved update before dispatching the next file.
					updateErr = client.Refresh(ctx)
				}
				return nil
			})
			command := &pb.CmdVirusScan{TaskId: "pinned-before-update", Mode: pb.CmdVirusScan_CUSTOM, Paths: paths, Engine: "yara", ExecutionContract: 4, ExpectedDbVersion: oldVersion}
			result := engine.ScanCommand(context.Background(), command, work)
			if visits != 3 || yara.Code(updateErr) != fault.code {
				t.Fatal("approved update did not execute between files", visits, updateErr)
			}
			count, failed := 3, uint64(0)
			if fault.code == "" {
				count, failed = 1, 2
			}
			var expectedBytes uint64
			for _, path := range paths[:count] {
				expectedBytes += uint64(len(contents[path]))
			}
			checkBoundaryTask(t, result, "yara", oldVersion, "yara_version_changed", count, expectedBytes)
			if status := client.Status(); status.Scans != 3 || status.Failures != failed || status.Update.LastIssue != fault.code {
				t.Fatal("task confused update failures and per-file version failures", status)
			}
			if count == 1 {
				for i, issue := range result.Issues {
					if issue.Path != paths[i+1] {
						t.Fatal("version failure attributed to a different file", result.Issues)
					}
				}
				for _, path := range paths[1:] {
					if content, err := os.ReadFile(path); err != nil || !bytes.Equal(content, contents[path]) {
						t.Fatal("old task acted on a file using the new rules", path, err)
					}
				}
			}
			historical := proto.Clone(result)
			restoreBoundaryFindings(t, work, result, "BeforeTaskUpdate", contents)
			if fault.code != "" {
				publish(taskAfterRules, http.StatusOK)
				if err := client.Refresh(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			command.TaskId, command.ExpectedDbVersion = "pinned-after-update", newVersion
			fresh := engine.ScanCommand(context.Background(), command, work)
			total := uint64(0)
			for _, content := range contents {
				total += uint64(len(content))
			}
			checkBoundaryTask(t, fresh, "yara", newVersion, "", 3, total)
			restoreBoundaryFindings(t, work, fresh, "AfterTaskUpdate", contents)
			if !proto.Equal(result, historical) || client.Status().Scans != 6 || client.Status().Failures != failed || client.Status().Update.LastIssue != "" {
				t.Fatal("new task rewrote old evidence or lost cumulative failure accounting", result, client.Status())
			}
		})
	}
}

func TestClamavTaskPinsVersionAcrossDaemonUpdate(t *testing.T) {
	const nextVersion = "ClamAV 1.4.6/updated-fixture"
	for _, timing := range []string{"between-files", "before-first-verdict-validation"} {
		t.Run(timing, func(t *testing.T) {
			var version atomic.Value
			version.Store(clamVersion)
			var streams atomic.Int64
			cfg := clamavtest.Start(t, func(conn net.Conn) {
				command, err := clamavtest.Command(conn)
				if err != nil {
					return
				}
				if command == "zVERSION\x00" {
					clamavtest.Reply(conn, version.Load().(string))
					return
				}
				if command != "zINSTREAM\x00" {
					return
				}
				if _, err := clamavtest.Stream(conn); err != nil {
					return
				}
				if streams.Add(1) == 1 && timing == "before-first-verdict-validation" {
					version.Store(nextVersion)
				}
				clamavtest.Reply(conn, "stream: Harmless.Task FOUND")
			})
			work := t.TempDir()
			client := clamav.New(cfg)
			engine := NewEngine(work, quietLogger())
			engine.SetClamAV(client)
			paths, contents := updateBoundaryFiles(t)
			visits := 0
			engine.SetIOBudget(func(_ context.Context, n int) error {
				if n == 4096 {
					visits++
					if visits == 2 && timing == "between-files" {
						version.Store(nextVersion)
					}
				}
				return nil
			})
			command := &pb.CmdVirusScan{TaskId: "clamav-before-update", Mode: pb.CmdVirusScan_CUSTOM, Paths: paths, Engine: "clamav", ExecutionContract: 3, ExpectedDbVersion: clamVersion}
			result := engine.ScanCommand(context.Background(), command, work)
			scanned := 1
			if timing == "before-first-verdict-validation" {
				scanned = 0
			}
			checkBoundaryTask(t, result, "clamav", clamVersion, "clamav_version_changed", scanned, uint64(len(contents[paths[0]])))
			if visits != 3 || streams.Load() != 1 || client.Status().Scans != 3 || client.Status().Failures != uint64(3-scanned) {
				t.Fatal("old task sent later files to the changed daemon or lost attempts", streams.Load(), client.Status())
			}
			for i, issue := range result.Issues {
				if issue.Path != paths[i+scanned] {
					t.Fatal("daemon version failure attributed to a different file", result.Issues)
				}
			}
			for _, path := range paths[scanned:] {
				if content, err := os.ReadFile(path); err != nil || !bytes.Equal(content, contents[path]) {
					t.Fatal("changed daemon authorized an unpinned disposition", path, err)
				}
			}
			historical := proto.Clone(result)
			restoreBoundaryFindings(t, work, result, "Harmless.Task", contents)
			command.TaskId, command.ExpectedDbVersion = "clamav-after-update", nextVersion
			fresh := engine.ScanCommand(context.Background(), command, work)
			total := uint64(0)
			for _, content := range contents {
				total += uint64(len(content))
			}
			checkBoundaryTask(t, fresh, "clamav", nextVersion, "", 3, total)
			restoreBoundaryFindings(t, work, fresh, "Harmless.Task", contents)
			if !proto.Equal(result, historical) || streams.Load() != 4 || client.Status().Scans != 6 || client.Status().Failures != uint64(3-scanned) {
				t.Fatal("fresh task lost prior evidence, failure counts or native stream bounds", client.Status())
			}
		})
	}
}
