//go:build linux || windows

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/config"
	"github.com/alinksec/alinksec-agent/internal/configguard"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"gopkg.in/yaml.v3"
)

type configProcess struct {
	binary, work string
	cmd          *exec.Cmd
	log          *os.File
}

func (p *configProcess) start(t *testing.T) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(filepath.Dir(p.work), "agent-process.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	p.log = f
	p.cmd = exec.Command(p.binary, "run", "--workdir", p.work)
	p.cmd.Stdout = f
	p.cmd.Stderr = f
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
}
func (p *configProcess) stop(t *testing.T) {
	t.Helper()
	if p.cmd == nil {
		return
	}
	_ = p.cmd.Process.Kill()
	_ = p.cmd.Wait()
	_ = p.log.Close()
	p.cmd = nil
}
func (p *configProcess) pid(t *testing.T) int { t.Helper(); return p.cmd.Process.Pid }
func (p *configProcess) restartWatchdog(t *testing.T) {
	t.Fatal("configuration test has no upgrade watchdog")
}

func waitConfigCondition(t *testing.T, description string, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal(description)
}

func readConfigEvents(t *testing.T, work string) []configguard.Event {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(work, "config-integrity", "record.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		Events []configguard.Event `json:"events"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r.Events
}

func TestConfigIntegrityLifecycle(t *testing.T) {
	native := os.Getenv("ALINKSEC_CONFIG_NATIVE_REQUIRED") == "true"
	if !native && os.Getenv("ALINKSEC_CONFIG_PROCESS_REQUIRED") != "true" {
		t.Skip("requires explicitly selected actual Agent validation")
	}
	if native && (os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted") {
		t.Fatal("native service fixtures require disposable GitHub-hosted runners")
	}
	source := os.Getenv("ALINKSEC_SMOKE_AGENT_BIN")
	if !filepath.IsAbs(source) {
		t.Fatal("actual Agent binary path must be absolute")
	}
	root := filepath.Join(t.TempDir(), "Config Integrity With Spaces")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	name := "alinksec-agent"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binary := filepath.Join(root, name)
	built, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, built, 0700); err != nil {
		t.Fatal(err)
	}
	fixture, address, ca := newSCMFixture(t, root)
	work := filepath.Join(root, "Agent Work Directory")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, binary, "install", "--server", address, "--token", "ENROLL-windows-scm-fixture", "--ca-file", ca, "--workdir", work).CombinedOutput(); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	path := filepath.Join(work, "agent.yml")
	cfg, err := config.Load(path)
	if err != nil || cfg.EnrollToken != "" {
		t.Fatalf("bootstrap secret not cleared: %v", err)
	}
	disabled := false
	cfg.Decoy = config.DecoyConfig{Enabled: &disabled, Response: "alert_only"}
	cfg.HeartbeatInterval = time.Second
	cfg.CollectInterval = 24 * time.Hour
	good, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	applyNativeConfig(t, binary, work, good)
	certPath := filepath.Join(work, "certs", "client.crt")
	cert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	certSHA := sha256.Sum256(cert)
	var service upgradeTestService
	if native {
		service = newUpgradeTestService(t, binary, work)
	} else {
		p := &configProcess{binary: binary, work: work}
		service = p
		t.Cleanup(func() { p.stop(t) })
	}
	service.start(t)
	connection := fixture.nextConnection(t)
	fixture.awaitReport(t, connection.number, func(r *pb.Report) bool { return r.GetHeartbeat() != nil })
	fixture.awaitReport(t, connection.number, func(r *pb.Report) bool {
		return r.GetAck().GetStage() == pb.RptAck_DONE && strings.HasPrefix(r.GetAck().GetCmdId(), "scm-policy-")
	})
	awaitEvent := func(session uint32, file string) *pb.Report {
		return fixture.awaitReport(t, session, func(r *pb.Report) bool {
			if r.GetSecurityEvent().GetRuleId() != "agent-config-integrity" {
				return false
			}
			var e configguard.Event
			return json.Unmarshal([]byte(r.GetSecurityEvent().GetDetail()), &e) == nil && e.File == file
		})
	}
	if err := os.WriteFile(path, []byte("server_addr: 127.0.0.1:1\ndecoy:\n  enabled: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	awaitEvent(connection.number, "agent.yml")
	if b, _ := os.ReadFile(path); !bytes.Equal(b, good) {
		t.Fatal("online configuration was not restored")
	}
	policyPath := filepath.Join(work, "policy.json")
	policy, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, []byte(`{"virus_realtime":{"enabled":false,"action":"alert_only"},"virus_whitelist":[{"type":"path","value":"/"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	awaitEvent(connection.number, "policy.json")
	if b, _ := os.ReadFile(policyPath); !bytes.Equal(b, policy) {
		t.Fatal("authenticated policy shadow not restored")
	}

	fixture.denyChannels.Store(true)
	fixture.disconnect <- struct{}{}
	waitConfigCondition(t, "authenticated channel remained connected", func() bool { return fixture.activeChannels.Load() == 0 })
	count := len(readConfigEvents(t, work))
	if err := os.WriteFile(path, []byte("server_addr: [invalid yaml\nenroll_token: do-not-leak-this-content\n"), 0600); err != nil {
		t.Fatal(err)
	}
	waitConfigCondition(t, "offline tamper was not journaled", func() bool { return len(readConfigEvents(t, work)) > count })
	offlineEvents := readConfigEvents(t, work)
	offlineID := offlineEvents[len(offlineEvents)-1].ID
	service.stop(t)
	if err := os.WriteFile(path, []byte("not: [valid yaml\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(policyPath); err != nil {
		t.Fatal(err)
	}
	service.start(t)
	waitConfigCondition(t, "restart did not recover pinned configuration offline", func() bool { b, e := os.ReadFile(path); return e == nil && bytes.Equal(b, good) })
	fixture.denyChannels.Store(false)
	reconnected := fixture.nextConnection(t)
	fixture.awaitReport(t, reconnected.number, func(r *pb.Report) bool { return r.GetHeartbeat() != nil })
	replayed := fixture.awaitReport(t, reconnected.number, func(r *pb.Report) bool { return r.GetReportId() == offlineID+"-config-event" })
	if replayed.GetSecurityEvent().GetActionTaken() != "trusted_config_in_use" {
		t.Fatal("replay claimed incorrect recovery action")
	}
	if b, _ := os.ReadFile(certPath); sha256.Sum256(b) != certSHA || fixture.enrollments.Load() != 1 {
		t.Fatal("tamper recovery changed certificates or re-enrolled")
	}

	// The lock must reject a legitimate-looking local apply while running.
	candidate := filepath.Join(root, "locked-candidate.yml")
	if err := os.WriteFile(candidate, good, 0600); err != nil {
		t.Fatal(err)
	}
	lockedCtx, lockedCancel := context.WithTimeout(context.Background(), 10*time.Second)
	out, applyErr := exec.CommandContext(lockedCtx, binary, "config", "apply", "--from", candidate, "--workdir", work).CombinedOutput()
	lockedCancel()
	if applyErr == nil || !bytes.Contains(out, []byte("locked")) {
		t.Fatalf("active configuration apply was not locked: %v %s", applyErr, out)
	}
	service.stop(t)
	if err := os.WriteFile(candidate, []byte("unknown_credential_field: must-not-be-echoed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	badCtx, badCancel := context.WithTimeout(context.Background(), 10*time.Second)
	out, applyErr = exec.CommandContext(badCtx, binary, "config", "apply", "--from", candidate, "--workdir", work).CombinedOutput()
	badCancel()
	if applyErr == nil || bytes.Contains(out, []byte("must-not-be-echoed")) {
		t.Fatal("invalid local apply accepted or leaked contents")
	}
	cfg.HeartbeatInterval = 2 * time.Second
	updated, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	applyNativeConfig(t, binary, work, updated)
	service.start(t)
	final := fixture.nextConnection(t)
	fixture.awaitReport(t, final.number, func(r *pb.Report) bool { return r.GetHeartbeat() != nil })
	service.stop(t)
	if b, _ := os.ReadFile(path); !bytes.Equal(b, updated) {
		t.Fatal("authorized offline config not retained")
	}
	events := readConfigEvents(t, work)
	encoded, _ := json.Marshal(events)
	if bytes.Contains(encoded, []byte("do-not-leak-this-content")) || bytes.Contains(encoded, []byte("ENROLL-windows-scm-fixture")) {
		t.Fatal("credential leaked to evidence")
	}
	for _, e := range events {
		if len(e.ID) != 32 || e.Action != "trusted_config_in_use" {
			t.Fatal("invalid durable event identity")
		}
	}
	checks := []string{"verified-enrollment", "bootstrap-credential-cleared", "explicit-offline-apply", "authenticated-policy-pinned", "online-config-tamper-recovered", "online-policy-tamper-recovered", "offline-event-journaled", "restart-with-invalid-config-and-missing-policy", "stable-event-replay", "certificate-identity-preserved", "active-apply-rejected", "invalid-apply-redacted", "authorized-update-survives-restart"}
	result := map[string]any{"success": true, "os": runtime.GOOS, "arch": runtime.GOARCH, "nativeService": native, "checks": checks, "events": events}
	if output := os.Getenv("ALINKSEC_CONFIG_EVIDENCE_FILE"); output != "" {
		if err := os.MkdirAll(filepath.Dir(output), 0700); err != nil {
			t.Fatal(err)
		}
		b, _ := json.MarshalIndent(result, "", "  ")
		if err := os.WriteFile(output, append(b, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("actual Agent config integrity checks passed: native_service=%t checks=%d", native, len(checks))
}
