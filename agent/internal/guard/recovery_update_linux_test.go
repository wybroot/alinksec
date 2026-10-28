//go:build linux

package guard

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/config"
	"github.com/alinksec/alinksec-agent/internal/configguard"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/virusscan"
	"github.com/alinksec/alinksec-agent/internal/yara"
	"github.com/alinksec/alinksec-agent/internal/yara/yaratest"
)

const recoveryBeforeRules = `rule BeforeUpdate { strings: $s="harmless before update marker" condition: $s }`
const recoveryAfterRules = `rule AfterUpdate { strings: $s="harmless after update marker" condition: $s }`

type recoveryRulePublisher struct {
	mu     sync.Mutex
	source string
	status int
	served chan struct{}
}

func (p *recoveryRulePublisher) publish(source string, status int, served chan struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.source, p.status, p.served = source, status, served
}

func newRecoveryRulePublisher(t *testing.T) (*recoveryRulePublisher, yara.Config) {
	t.Helper()
	_, _ = yaratest.Native(t)
	p := &recoveryRulePublisher{source: recoveryBeforeRules, status: http.StatusOK}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		source, status, served := p.source, p.status, p.served
		p.mu.Unlock()
		w.WriteHeader(status)
		_, _ = io.WriteString(w, source)
		if served != nil {
			select {
			case served <- struct{}{}:
			default:
			}
		}
	}))
	t.Cleanup(server.Close)
	ca := filepath.Join(t.TempDir(), "publisher-ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	return p, yara.Config{Enabled: true, Realtime: true, UpdateURL: server.URL + "/approved.yar", UpdateCAFile: ca, TimeoutSec: 10}
}

type nativeUpdateRecovery struct {
	guard    *Guard
	client   *yara.Client
	contents map[string][]byte
	reports  []*pb.RptSecurityEvent
	checks   int
}

func newNativeUpdateRecovery(t *testing.T, cfg yara.Config, files map[string]string, wait func(context.Context, int) error) *nativeUpdateRecovery {
	t.Helper()
	f := &nativeUpdateRecovery{contents: make(map[string][]byte)}
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		f.contents[path] = []byte(content)
	}
	disabled := false
	f.guard = New(&config.DecoyConfig{Enabled: &disabled}, nil, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)), func(report *pb.RptSecurityEvent) {
		f.reports = append(f.reports, report)
	})
	t.Cleanup(func() {
		if f.guard.virusRecovery != nil {
			f.guard.virusRecovery.Close()
		}
	})
	f.client = yara.NewWithUpdates(cfg, configguard.ReadFile, f.guard.workDir)
	if err := f.client.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.setClient(f.client, `{"virus_realtime":{"enabled":true,"action":"alert_only"}}`, wait)
	f.guard.SetVirusRoots([]string{root}, nil)
	// The native event collector stays stopped. No update or fixture can deliver
	// a file event; only explicitly advancing periodic recovery revisits files.
	f.guard.updateFileWatches()
	return f
}

func (f *nativeUpdateRecovery) setClient(client *yara.Client, policy string, wait func(context.Context, int) error) {
	f.client = client
	engine := virusscan.NewEngineWithPolicyReader(f.guard.workDir, f.guard.log, func() ([]byte, error) {
		return []byte(policy), nil
	})
	engine.SetYARA(f.client)
	engine.SetIOBudget(wait)
	f.guard.SetVirusEngine(func(path string) *pb.VirusFinding {
		f.checks++
		return engine.CheckRealtime(path, f.guard.workDir)
	})
}

func (f *nativeUpdateRecovery) sweep(t *testing.T) {
	t.Helper()
	before := f.checks
	f.guard.virusRescan = true // advance the existing 60-second request
	for n := 0; n < 20; n++ {
		f.guard.fileEventLoop()
		if f.guard.virusRecovery == nil && !f.guard.virusRescan {
			if f.checks-before != len(f.contents) {
				t.Fatalf("recovery skipped files or retried eagerly: checks=%d files=%d", f.checks-before, len(f.contents))
			}
			return
		}
	}
	t.Fatal("periodic recovery did not complete")
}

func (f *nativeUpdateRecovery) finding(t *testing.T, index int, file, name, rules string) {
	t.Helper()
	if len(f.reports) != index+1 || f.reports[index].Type != "virus" {
		t.Fatalf("incorrect recovery reports: want=%d reports=%v", index+1, f.reports)
	}
	var finding struct {
		Name         string   `json:"name"`
		Path         string   `json:"path"`
		SHA256       string   `json:"sha256"`
		Size         uint64   `json:"size"`
		Engine       string   `json:"engine"`
		Version      string   `json:"engine_version"`
		Action       string   `json:"action"`
		QuarantineID string   `json:"quarantine_id"`
		ActionError  string   `json:"action_error"`
		MatchedRules []string `json:"matched_rules"`
	}
	if err := json.Unmarshal([]byte(f.reports[index].Detail), &finding); err != nil {
		t.Fatal(err)
	}
	content, found := f.contents[finding.Path]
	if !found || filepath.Base(finding.Path) != file || finding.Engine != "yara" || finding.Name != name || finding.Version != fmt.Sprintf("YARA 4.5.8/sha256:%x", sha256.Sum256([]byte(rules))) || finding.SHA256 != fmt.Sprintf("%x", sha256.Sum256(content)) || finding.Size != uint64(len(content)) || len(finding.MatchedRules) != 1 || finding.MatchedRules[0] != name || finding.Action != "alert_only" || finding.QuarantineID != "" || finding.ActionError != "" {
		t.Fatalf("report mixed rule, file or disposition evidence: %+v", finding)
	}
	for path, expected := range f.contents {
		if current, err := os.ReadFile(path); err != nil || string(current) != string(expected) {
			t.Fatal("alert-only recovery moved or changed a fixture", path, err)
		}
	}
}

func TestNativeYARARecoveryUsesApprovedUpdatesAfterFailure(t *testing.T) {
	for _, fault := range []struct{ name, source, code string }{
		{"download", "upstream unavailable", "yara_update_download"},
		{"compile", "rule Broken { condition: }", "yara_compile_error"},
	} {
		t.Run(fault.name, func(t *testing.T) {
			publisher, cfg := newRecoveryRulePublisher(t)
			f := newNativeUpdateRecovery(t, cfg, map[string]string{
				"old-marker": "harmless before update marker",
				"new-marker": "harmless after update marker",
			}, nil)
			f.sweep(t)
			f.finding(t, 0, "old-marker", "BeforeUpdate", recoveryBeforeRules)
			oldVersion := f.client.Status().Version
			snapshotPath := filepath.Join(f.guard.workDir, "yara-updates/current.json")
			before, err := os.ReadFile(snapshotPath)
			if err != nil {
				t.Fatal(err)
			}
			status := http.StatusOK
			if fault.name == "download" {
				status = http.StatusServiceUnavailable
			}
			publisher.publish(fault.source, status, nil)
			if err := f.client.Refresh(context.Background()); yara.Code(err) != fault.code {
				t.Fatal("unexpected update failure", err)
			}
			failed := f.client.Status()
			if failed.State != "ready" || failed.Version != oldVersion || failed.Update.LastIssue != fault.code || failed.Update.NextCheckAt <= failed.Update.CheckedAt {
				t.Fatalf("failed candidate lost readiness or retry evidence: %+v", failed)
			}
			if after, err := os.ReadFile(snapshotPath); err != nil || string(after) != string(before) {
				t.Fatal("failed candidate replaced the working snapshot", err)
			}
			f.sweep(t)
			f.finding(t, 1, "old-marker", "BeforeUpdate", recoveryBeforeRules)
			if after := f.client.Status(); after.Update != failed.Update || after.Failures != 0 || after.Scans != 4 {
				t.Fatalf("successful old-rule recovery erased update failure or counted it as a scan failure: %+v", after)
			}
			publisher.publish(recoveryAfterRules, http.StatusOK, nil)
			if err := f.client.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			f.sweep(t)
			f.finding(t, 2, "new-marker", "AfterUpdate", recoveryAfterRules)
			if after := f.client.Status(); after.Update.LastIssue != "" || after.Version == oldVersion || after.Failures != 0 || after.Scans != 6 {
				t.Fatalf("next recovery did not use the repaired update: %+v", after)
			}
		})
	}
}

func TestNativeYARARecoveryPinsRulesWhileApprovedUpdateWaits(t *testing.T) {
	publisher, cfg := newRecoveryRulePublisher(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	updated, served := make(chan error, 1), make(chan struct{}, 1)
	started, finished := false, false
	var f *nativeUpdateRecovery
	f = newNativeUpdateRecovery(t, cfg, map[string]string{
		"both-markers": "harmless before update marker; harmless after update marker",
	}, func(scanCtx context.Context, _ int) error {
		if started {
			return nil
		}
		started = true
		publisher.publish(recoveryAfterRules, http.StatusOK, served)
		go func() { updated <- f.client.Refresh(ctx) }()
		select {
		case <-served:
		case <-scanCtx.Done():
			return scanCtx.Err()
		}
		select {
		case err := <-updated:
			finished = true
			return fmt.Errorf("update finished while file input held the scan gate: %v", err)
		default:
		}
		if version := f.client.Status().Version; version != fmt.Sprintf("YARA 4.5.8/sha256:%x", sha256.Sum256([]byte(recoveryBeforeRules))) {
			return fmt.Errorf("update replaced active input rules: %s", version)
		}
		return nil
	})
	t.Cleanup(func() {
		cancel()
		if started && !finished {
			select {
			case <-updated:
			case <-time.After(2 * time.Second):
				t.Error("update goroutine did not stop")
			}
		}
	})
	f.sweep(t)
	f.finding(t, 0, "both-markers", "BeforeUpdate", recoveryBeforeRules)
	select {
	case err := <-updated:
		finished = true
		if err != nil {
			t.Fatal("queued update failed", err)
		}
	case <-ctx.Done():
		t.Fatal("queued update did not complete", ctx.Err())
	}
	f.sweep(t)
	f.finding(t, 1, "both-markers", "AfterUpdate", recoveryAfterRules)
	if status := f.client.Status(); status.Scans != 2 || status.Failures != 0 || status.Update.LastIssue != "" {
		t.Fatalf("serialized update produced a scan failure: %+v", status)
	}
}
