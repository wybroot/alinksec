//go:build linux

package guard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/alinksec/alinksec-agent/internal/config"
	"github.com/alinksec/alinksec-agent/internal/configguard"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/virusscan"
	"github.com/alinksec/alinksec-agent/internal/yara"
)

func TestNativeYARARecoveryRestartsOfflineWithoutCrossingSourceIdentity(t *testing.T) {
	publisher, cfg := newRecoveryRulePublisher(t)
	f := newNativeUpdateRecovery(t, cfg, map[string]string{"marker": "harmless after update marker"}, nil)
	f.sweep(t)
	if len(f.reports) != 0 {
		t.Fatal("bootstrap rules unexpectedly matched the new marker")
	}
	publisher.publish(recoveryAfterRules, http.StatusOK, nil)
	if err := f.client.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.sweep(t)
	f.finding(t, 0, "marker", "AfterUpdate", recoveryAfterRules)
	snapshot := filepath.Join(f.guard.workDir, "yara-updates/current.json")
	before, err := os.ReadFile(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	version := f.client.Status().Version
	publisher.publish("offline publisher", http.StatusServiceUnavailable, nil)

	// Reconstruct all three objects with only their persisted work directory and
	// configured roots. No live client, engine, sweep cursor or clean cache survives.
	roots, _ := f.guard.virusRoots()
	work, log := f.guard.workDir, f.guard.log
	disabled := false
	f.guard = New(&config.DecoyConfig{Enabled: &disabled}, nil, work, log, func(report *pb.RptSecurityEvent) {
		f.reports = append(f.reports, report)
	})
	f.guard.SetVirusRoots(roots, nil)
	f.setClient(yara.NewWithUpdates(cfg, configguard.ReadFile, work), `{"virus_realtime":{"enabled":true,"action":"alert_only"}}`, nil)
	f.guard.updateFileWatches()
	if v, err := f.client.Probe(context.Background()); err != nil || v != version || f.client.Status().Scans != 0 {
		t.Fatal("fresh client did not load the exact persisted revision", v, err, f.client.Status())
	}
	if err := f.client.Refresh(context.Background()); yara.Code(err) != "yara_update_download" {
		t.Fatal("offline update was not reported", err)
	}
	f.sweep(t)
	f.finding(t, 1, "marker", "AfterUpdate", recoveryAfterRules)
	status := f.client.Status()
	if status.State != "ready" || status.Version != version || status.Update.LastIssue != "yara_update_download" || status.Scans != 1 || status.Failures != 0 {
		t.Fatalf("offline recovery lost last-known rules or update evidence: %+v", status)
	}
	if after, err := os.ReadFile(snapshot); err != nil || !bytes.Equal(before, after) {
		t.Fatal("offline restart changed the working snapshot", err)
	}

	// Changing an approved URL invalidates the old authority's snapshot. Even an
	// identical marker cannot authorize a finding before that new source succeeds.
	cfg.UpdateURL += "/different-authority"
	f.setClient(yara.NewWithUpdates(cfg, configguard.ReadFile, work), `{"virus_realtime":{"enabled":true,"action":"alert_only"}}`, nil)
	if err := f.client.Refresh(context.Background()); yara.Code(err) != "yara_update_download" {
		t.Fatal(err)
	}
	f.sweep(t)
	if len(f.reports) != 2 || f.client.Status().Scans != 0 || f.client.Status().State != "unavailable" {
		t.Fatal("recovery reused another source's snapshot", f.reports, f.client.Status())
	}
	if after, err := os.ReadFile(snapshot); err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed new source overwrote the prior authority's snapshot", err)
	}
	publisher.publish(recoveryAfterRules, http.StatusOK, nil)
	if err := f.client.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.sweep(t)
	f.finding(t, 2, "marker", "AfterUpdate", recoveryAfterRules)
	if f.client.Status().Update.LastIssue != "" || f.client.Status().Failures != 0 {
		t.Fatal("new approved source did not recover", f.client.Status())
	}
}

func TestNativeYARARecoveryRetiresRulesAfterExactQuarantineRestore(t *testing.T) {
	publisher, cfg := newRecoveryRulePublisher(t)
	f := newNativeUpdateRecovery(t, cfg, map[string]string{"marker": "harmless before update marker"}, nil)
	f.setClient(f.client, `{"virus_realtime":{"enabled":true,"action":"quarantine"}}`, nil)
	f.sweep(t)
	if len(f.reports) != 1 {
		t.Fatal("recovery did not report quarantine", f.reports)
	}
	type quarantineFinding struct {
		Path    string   `json:"path"`
		SHA256  string   `json:"sha256"`
		Size    uint64   `json:"size"`
		Engine  string   `json:"engine"`
		Version string   `json:"engine_version"`
		Action  string   `json:"action"`
		ID      string   `json:"quarantine_id"`
		Error   string   `json:"action_error"`
		Rules   []string `json:"matched_rules"`
	}
	var finding quarantineFinding
	if err := json.Unmarshal([]byte(f.reports[0].Detail), &finding); err != nil {
		t.Fatal(err)
	}
	content, ok := f.contents[finding.Path]
	if !ok || finding.SHA256 != fmt.Sprintf("%x", sha256.Sum256(content)) || finding.Size != uint64(len(content)) || finding.Engine != "yara" || finding.Version != f.client.Status().Version || finding.Action != "quarantined" || finding.ID == "" || finding.Error != "" || len(finding.Rules) != 1 || finding.Rules[0] != "BeforeUpdate" {
		t.Fatalf("quarantine report lost exact detection evidence: %+v", finding)
	}
	if _, err := os.Lstat(finding.Path); !os.IsNotExist(err) {
		t.Fatal("quarantine left the original file", err)
	}
	quarantine := virusscan.NewQuarantine(f.guard.workDir)
	if exported, err := quarantine.ExportExpected(context.Background(), finding.Path, finding.ID, finding.SHA256, 1<<20); err != nil || !bytes.Equal(exported, content) {
		t.Fatal("quarantined evidence differs from the reported bytes", err)
	}
	if err := quarantine.RestoreExpected(context.Background(), finding.Path, finding.ID, finding.SHA256); err != nil {
		t.Fatal(err)
	}
	if restored, err := os.ReadFile(finding.Path); err != nil || !bytes.Equal(restored, content) {
		t.Fatal("restored bytes differ from detection", err)
	}
	if st, err := os.Stat(finding.Path); err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("restore changed the original permissions", err)
	}
	report := f.reports[0].Detail
	publisher.publish(recoveryAfterRules, http.StatusOK, nil)
	if err := f.client.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.sweep(t)
	if len(f.reports) != 1 || f.reports[0].Detail != report || f.client.Status().Version == finding.Version || f.client.Status().Scans != 2 || f.client.Status().Failures != 0 {
		t.Fatal("retired rule still triggered quarantine or rewrote historical evidence", f.reports, f.client.Status())
	}
	if restored, err := os.ReadFile(finding.Path); err != nil || !bytes.Equal(restored, content) {
		t.Fatal("retired rule moved or changed the restored file", err)
	}
	// The same long-lived engine must detect the unchanged restored bytes when
	// the rule returns, without reusing the intervening clean result.
	publisher.publish(recoveryBeforeRules, http.StatusOK, nil)
	if err := f.client.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.sweep(t)
	if len(f.reports) != 2 {
		t.Fatal("restored rule did not detect the unchanged file", f.reports)
	}
	var repeated quarantineFinding
	if err := json.Unmarshal([]byte(f.reports[1].Detail), &repeated); err != nil {
		t.Fatal(err)
	}
	if repeated.Path != finding.Path || repeated.SHA256 != finding.SHA256 || repeated.Size != finding.Size || repeated.Engine != finding.Engine || repeated.Version != finding.Version || repeated.Action != "quarantined" || repeated.ID == "" || repeated.ID == finding.ID || repeated.Error != "" || len(repeated.Rules) != 1 || repeated.Rules[0] != "BeforeUpdate" {
		t.Fatalf("reintroduced rule mixed evidence or reused the old capture: %+v", repeated)
	}
	if f.reports[0].Detail != report || f.client.Status().Scans != 3 || f.client.Status().Failures != 0 {
		t.Fatal("restored rule lost historical evidence or scan accounting", f.client.Status())
	}
	if err := quarantine.RestoreExpected(context.Background(), repeated.Path, repeated.ID, repeated.SHA256); err != nil {
		t.Fatal(err)
	}
	if restored, err := os.ReadFile(repeated.Path); err != nil || !bytes.Equal(restored, content) {
		t.Fatal("second restore changed the original bytes", err)
	}
}
