//go:build linux

package guard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"log/slog"

	"github.com/alinksec/alinksec-agent/internal/config"
	"github.com/alinksec/alinksec-agent/internal/configguard"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/virusscan"
	"github.com/alinksec/alinksec-agent/internal/yara"
	"github.com/alinksec/alinksec-agent/internal/yara/yaratest"
)

func TestNativeYARARecoveryRetriesTransientInputFailure(t *testing.T) {
	cfg, version := yaratest.Native(t)
	for _, sample := range []struct{ name, reason, code string }{
		{"missing", "file_missing", "yara_read_failed_or_changed"},
		{"changed", "file_changed", "yara_read_failed_or_changed"},
		{"timeout", "timeout", "yara_timeout"},
	} {
		t.Run(sample.name, func(t *testing.T) {
			root := t.TempDir()
			path, held := filepath.Join(root, "marker"), filepath.Join(t.TempDir(), "held")
			data := []byte(yaratest.Marker)
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			var reports []*pb.RptSecurityEvent
			disabled := false
			g := New(&config.DecoyConfig{Enabled: &disabled}, nil, t.TempDir(), slog.New(slog.NewJSONHandler(&logs, nil)), func(e *pb.RptSecurityEvent) { reports = append(reports, e) })
			defer func() {
				if g.virusRecovery != nil {
					g.virusRecovery.Close()
				}
			}()
			client := yara.New(cfg, configguard.ReadFile)
			engine := virusscan.NewEngineWithPolicyReader(g.workDir, g.log, func() ([]byte, error) {
				return []byte(`{"virus_realtime":{"enabled":true,"action":"alert_only"}}`), nil
			})
			engine.SetYARA(client)
			var fault atomic.Bool
			fault.Store(true)
			engine.SetIOBudget(func(ctx context.Context, _ int) error {
				if sample.name == "timeout" && fault.Load() {
					<-ctx.Done()
					return ctx.Err()
				}
				if sample.name == "changed" && fault.CompareAndSwap(true, false) {
					return os.WriteFile(path, append(append([]byte(nil), data...), 'x'), 0600)
				}
				return nil
			})
			checks := 0
			g.SetVirusRoots([]string{root}, nil)
			g.SetVirusEngine(func(p string) *pb.VirusFinding {
				checks++
				if sample.name == "missing" && fault.CompareAndSwap(true, false) {
					if err := os.Rename(path, held); err != nil {
						t.Fatal(err)
					}
				}
				return engine.CheckRealtime(p, g.workDir)
			})
			// Do not start the event collector. Repair cannot deliver a new
			// file event; only the next periodic recovery request can revisit it.
			g.updateFileWatches()
			finish := func() {
				t.Helper()
				g.fileEventLoop()
				for n := 0; n < 8 && g.virusRecovery != nil; n++ {
					g.fileEventLoop()
				}
				if g.virusRecovery != nil || g.virusRescan {
					t.Fatal("bounded recovery did not complete")
				}
			}
			started := time.Now()
			finish()
			if checks != 1 || len(reports) != 0 || time.Since(started) > 4*time.Second {
				t.Fatalf("failed recovery produced an action, retried eagerly or exceeded its deadline: checks=%d reports=%v", checks, reports)
			}
			failed := client.Status()
			if failed.Scans != 1 || failed.Failures != 1 || failed.ScanFailures.Counts[sample.code] != 1 || failed.ScanFailures.LastIssue != sample.code || failed.ScanFailures.LastAt == 0 {
				t.Fatalf("failed recovery lost native failure evidence: %+v", failed)
			}
			var diagnostic struct {
				Engine string `json:"engine"`
				Phase  string `json:"phase"`
				Reason string `json:"reason"`
			}
			if err := json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &diagnostic); err != nil || diagnostic.Engine != "yara" || diagnostic.Phase != "input" || diagnostic.Reason != sample.reason {
				t.Fatalf("incorrect failure diagnostic: %s err=%v", logs.Bytes(), err)
			}
			var traversal struct {
				Issue string `json:"recovery_issue"`
				Last  int64  `json:"last_sweep_at"`
			}
			if err := json.Unmarshal([]byte(g.FileWatchStatus()), &traversal); err != nil || traversal.Issue != "" || traversal.Last == 0 {
				t.Fatalf("file read failure confused with directory traversal: %+v err=%v", traversal, err)
			}
			if sample.name == "missing" {
				if err := os.Rename(held, path); err != nil {
					t.Fatal(err)
				}
			}
			fault.Store(false)
			stable, err := os.ReadFile(path)
			if err != nil || !bytes.HasPrefix(stable, data) {
				t.Fatal("failed check changed or quarantined the fixture", err)
			}
			// The existing 60-second tick sets this flag. Advance that trigger
			// directly so this test does not depend on elapsed wall-clock time.
			g.virusRescan = true
			finish()
			if checks != 2 || len(reports) != 1 || reports[0].Type != "virus" {
				t.Fatalf("later recovery did not revisit the failed file: checks=%d reports=%v", checks, reports)
			}
			var finding struct {
				Engine  string   `json:"engine"`
				Version string   `json:"engine_version"`
				Path    string   `json:"path"`
				SHA256  string   `json:"sha256"`
				Action  string   `json:"action"`
				Rules   []string `json:"matched_rules"`
			}
			sum := sha256.Sum256(stable)
			if err := json.Unmarshal([]byte(reports[0].Detail), &finding); err != nil || finding.Engine != "yara" || finding.Version != version || finding.Path != path || finding.SHA256 != hex.EncodeToString(sum[:]) || finding.Action != "alert_only" || len(finding.Rules) != 2 {
				t.Fatalf("recovery report lost pinned native evidence: %+v err=%v", finding, err)
			}
			recovered := client.Status()
			if recovered.Scans != 2 || recovered.Failures != failed.Failures || recovered.ScanFailures.LastAt != failed.ScanFailures.LastAt || recovered.ScanFailures.LastIssue != failed.ScanFailures.LastIssue || recovered.ScanFailures.Counts[sample.code] != 1 || recovered.LastIssue != "" {
				t.Fatalf("successful recovery erased historical failures: failed=%+v recovered=%+v", failed, recovered)
			}
			if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, stable) {
				t.Fatal("alert-only recovery changed the fixture", err)
			}
		})
	}
}
