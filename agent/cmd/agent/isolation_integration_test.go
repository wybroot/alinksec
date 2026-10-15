//go:build windows || linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/config"
	"github.com/alinksec/alinksec-agent/internal/isolation"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"gopkg.in/yaml.v3"
)

func TestNativeIsolationLifecycle(t *testing.T) {
	if os.Getenv("ALINKSEC_ISOLATION_NATIVE_REQUIRED") != "true" {
		t.Skip("requires a disposable native service runner")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Fatal("native isolation requires a disposable GitHub-hosted runner")
	}
	source := os.Getenv("ALINKSEC_SMOKE_AGENT_BIN")
	if !filepath.IsAbs(source) {
		t.Fatal("absolute validated Agent binary required")
	}
	dnsCtx, dnsCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dnsCancel()
	addresses, err := net.DefaultResolver.LookupIP(dnsCtx, "ip4", "api.github.com")
	if err != nil || len(addresses) == 0 {
		t.Fatal("external TCP baseline endpoint unavailable", err)
	}
	probe := net.JoinHostPort(addresses[0].String(), "443")
	connects := func() bool {
		c, err := net.DialTimeout("tcp", probe, 1500*time.Millisecond)
		if err != nil {
			return false
		}
		c.Close()
		return true
	}
	if !connects() {
		t.Fatal("external TCP baseline must pass before any isolation mutation")
	}
	built, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "Isolation Installation With Spaces")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	name := "alinksec-agent"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binary := filepath.Join(root, name)
	if err := os.WriteFile(binary, built, 0700); err != nil {
		t.Fatal(err)
	}
	fixture, address, caFile := newSCMFixture(t, root)
	work := filepath.Join(root, "Agent Work Directory")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, binary, "install", "--server", address, "--token", "ENROLL-windows-scm-fixture", "--ca-file", caFile, "--workdir", work).CombinedOutput(); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	cfgPath := filepath.Join(work, "agent.yml")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	disabled := false
	cfg.Decoy = config.DecoyConfig{Enabled: &disabled, Response: "alert_only"}
	cfg.HeartbeatInterval = time.Second
	cfg.CollectInterval = 24 * time.Hour
	contents, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, contents, 0600); err != nil {
		t.Fatal(err)
	}
	certificate, err := os.ReadFile(filepath.Join(work, "certs", "client.crt"))
	if err != nil {
		t.Fatal(err)
	}
	certHash := sha256.Sum256(certificate)
	service := newUpgradeTestService(t, binary, work)
	prepareIsolationNative(t, work, addresses[0].String())
	service.start(t)
	connection := fixture.nextConnection(t)
	hb := fixture.awaitReport(t, connection.number, func(r *pb.Report) bool { return r.GetHeartbeat() != nil }).GetHeartbeat()
	if hb.GetIsolationContract() != 1 {
		t.Fatalf("native isolation contract not advertised: %+v", hb)
	}
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		l, err := isolation.Current(work)
		data, _ := json.Marshal(l)
		t.Logf("failure lease: %s (%v)", data, err)
		for _, r := range fixture.pending {
			if a := r.report.GetAck(); a != nil {
				t.Logf("pending ACK session=%d %s", r.session, a)
			}
		}
	})
	baseline := isolationNativePolicy(t)
	command := func(id string, action pb.CmdProtectAction_Action, contract uint32) *pb.Command {
		return &pb.Command{CmdId: id, Payload: &pb.Command_ProtectAction{ProtectAction: &pb.CmdProtectAction{Action: action, Reason: "disposable native validation", IsolationContract: contract}}}
	}
	awaitAck := func(id string, stage pb.RptAck_Stage) {
		t.Helper()
		t.Logf("waiting for %s ACK %s on session %d", id, stage, connection.number)
		fixture.awaitReport(t, connection.number, func(r *pb.Report) bool { return r.GetAck().GetCmdId() == id && r.GetAck().GetStage() == stage })
	}
	active := func(id string) *pb.RptIsolationState {
		t.Helper()
		return fixture.awaitReport(t, connection.number, func(r *pb.Report) bool {
			p := r.GetIsolationState()
			return p != nil && p.CommandId == id && p.Phase == "active" && p.Nonce != ""
		}).GetIsolationState()
	}
	echo := func(p *pb.RptIsolationState) {
		connection.commands <- &pb.Command{Payload: &pb.Command_IsolationConfirm{IsolationConfirm: &pb.CmdIsolationConfirm{LeaseId: p.LeaseId, Nonce: p.Nonce}}}
	}
	assertRestored := func() {
		l := waitIsolationLease(t, work, func(l *isolation.Lease) bool { return l.Phase == "finished" })
		if time.Now().After(l.Deadline.Add(3*time.Second)) && l.Cause == "lease_expired" {
			t.Fatal("healthy firewall cleanup exceeded the original lease deadline by more than three seconds")
		}
		if !connects() {
			t.Fatal("business networking not restored")
		}
		if isolationNativePolicy(t) != baseline {
			t.Fatal("pre-existing administrator firewall policy changed")
		}
		waitIsolationNativeRemoved(t)
	}
	connection.commands <- command("isolation-legacy-contract", pb.CmdProtectAction_ISOLATE_HOST, 0)
	awaitAck("isolation-legacy-contract", pb.RptAck_FAILED)
	if _, err := isolation.Current(work); !os.IsNotExist(err) {
		t.Fatal("legacy command mutated isolation state", err)
	}

	connection.commands <- command("isolation-confirmed", pb.CmdProtectAction_ISOLATE_HOST, 1)
	pulse := active("isolation-confirmed")
	if pulse.Confirmed {
		t.Fatal("isolation succeeded without a management round trip")
	}
	echo(pulse)
	awaitAck("isolation-confirmed", pb.RptAck_DONE)
	lease := waitIsolationLease(t, work, func(l *isolation.Lease) bool { return !l.Confirmed.IsZero() })
	if release, err := isolation.LockForRemoval(work); err == nil {
		release()
		t.Fatal("uninstall accepted an active isolation lease")
	}
	firstDeadline := lease.Deadline
	until := lease.Created.Add(11 * time.Second)
	for time.Now().Before(until) {
		echo(active("isolation-confirmed"))
	}
	lease, err = isolation.Current(work)
	if err != nil || lease.Phase != "active" || !lease.Deadline.After(firstDeadline) {
		t.Fatal("fresh confirmations did not sustain isolation past its original deadline", err)
	}
	if connects() {
		t.Fatal("business TCP bypassed isolation despite a pre-existing allow rule")
	}
	assertIsolationNativeRules(t, lease)
	connection.commands <- command("isolation-manual-restore", pb.CmdProtectAction_RESTORE_ISOLATION, 1)
	awaitAck("isolation-manual-restore", pb.RptAck_DONE)
	assertRestored()

	connection.commands <- command("isolation-no-echo", pb.CmdProtectAction_ISOLATE_HOST, 1)
	stalePulse := active("isolation-no-echo")
	if connects() {
		t.Fatal("unconfirmed isolation never blocked business networking")
	}
	// Windows rejects blocked TCP immediately; a one-second sleep can land
	// before the next send tick and replay a nonce that is still current.
	// Observe its actual replacement first, then replay only the obsolete nonce.
	replacement := active("isolation-no-echo")
	if replacement.Nonce == stalePulse.Nonce {
		t.Fatal("isolation challenge was reused")
	}
	for i := 0; i < 8; i++ {
		if current, _ := isolation.Current(work); current.Phase == "finished" {
			break
		}
		echo(stalePulse)
		time.Sleep(time.Second)
	}
	assertRestored()
	if expired, err := isolation.Current(work); err != nil || !expired.Confirmed.IsZero() {
		t.Fatal("obsolete nonce incorrectly confirmed isolation", err)
	}
	awaitAck("isolation-no-echo", pb.RptAck_FAILED)
	fixture.awaitReport(t, connection.number, func(r *pb.Report) bool {
		return r.GetSecurityEvent().GetRuleId() == "host-isolation-lease" && r.GetSecurityEvent().GetActionTaken() == "restored"
	})

	connection.commands <- command("isolation-main-stopped", pb.CmdProtectAction_ISOLATE_HOST, 1)
	pulse = active("isolation-main-stopped")
	echo(pulse)
	awaitAck("isolation-main-stopped", pb.RptAck_DONE)
	before, _ := isolation.Current(work)
	service.stop(t)
	assertRestored()
	after, _ := isolation.Current(work)
	if !after.Deadline.Equal(before.Deadline) {
		t.Fatal("Agent stop reset the persisted lease")
	}
	service.start(t)
	connection = fixture.nextConnection(t)
	awaitAck("isolation-main-stopped", pb.RptAck_DONE)
	fixture.awaitReport(t, connection.number, func(r *pb.Report) bool {
		return r.GetIsolationState().GetLeaseId() == after.ID && r.GetIsolationState().GetPhase() == "finished"
	})

	connection.commands <- command("isolation-owner-crashed", pb.CmdProtectAction_ISOLATE_HOST, 1)
	pulse = active("isolation-owner-crashed")
	echo(pulse)
	awaitAck("isolation-owner-crashed", pb.RptAck_DONE)
	before, _ = isolation.Current(work)
	crashIsolationNativeOwner(t)
	assertRestored()
	after, _ = isolation.Current(work)
	if !after.Deadline.Equal(before.Deadline) || after.Cause != "watchdog_restarted" {
		t.Fatalf("owner restart reapplied or renewed isolation: %+v", after)
	}
	pid := service.pid(t)
	connection.commands <- command("isolation-owner-crashed", pb.CmdProtectAction_ISOLATE_HOST, 1)
	awaitAck("isolation-owner-crashed", pb.RptAck_DONE)
	if current, _ := isolation.Current(work); current.ID != after.ID || current.Phase != "finished" || service.pid(t) != pid {
		t.Fatal("completed isolation command executed again")
	}
	certificate, err = os.ReadFile(filepath.Join(work, "certs", "client.crt"))
	if err != nil || sha256.Sum256(certificate) != certHash {
		t.Fatal("isolation recovery changed enrollment identity")
	}
	if path := os.Getenv("ALINKSEC_ISOLATION_EVIDENCE_FILE"); path != "" {
		data, _ := json.MarshalIndent(map[string]any{"os": runtime.GOOS, "arch": runtime.GOARCH, "success": true, "leaseSeconds": 10, "checks": []string{"legacy contract refused without mutation", "actual native system service with authenticated TLS round trip", "fresh confirmations sustain isolation beyond original deadline", "business IPv4 TCP blocked despite administrator allow rule", "IPv4/IPv6 owned policy installed", "manual restore completes only after owned rules removed", "missing fresh echo and replayed nonce independently restore within original deadline", "Agent stop does not prevent withdrawal or reset deadline", "keeper crash restores without reapplying isolation", "durable result/current state replay and command deduplication", "administrator firewall policy and enrollment identity preserved"}}, "", "  ")
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func waitIsolationLease(t *testing.T, work string, matches func(*isolation.Lease) bool) *isolation.Lease {
	t.Helper()
	until := time.Now().Add(18 * time.Second)
	for {
		l, err := isolation.Current(work)
		if err == nil && matches(l) {
			return l
		}
		if time.Now().After(until) {
			t.Fatalf("isolation did not reach expected state: %+v, %v", l, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func nativeIsolationCommand(t *testing.T, exe string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, exe, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("native isolation fixture %s %v: %v\n%.4096s", exe, args, err, out)
	}
	return strings.TrimSpace(string(out))
}
