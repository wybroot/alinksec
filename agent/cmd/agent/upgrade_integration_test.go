//go:build windows || linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/config"
	"github.com/alinksec/alinksec-agent/internal/identity"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/upgrade"
	"gopkg.in/yaml.v3"
)

type upgradeTestService interface {
	start(*testing.T)
	stop(*testing.T)
	pid(*testing.T) int
	restartWatchdog(*testing.T)
}

func TestNativeUpgradeLifecycle(t *testing.T) {
	if os.Getenv("ALINKSEC_UPGRADE_NATIVE_REQUIRED") != "true" {
		t.Skip("requires a disposable native service runner")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Fatal("native upgrade fixtures require disposable GitHub-hosted runners")
	}
	source, broken := os.Getenv("ALINKSEC_SMOKE_AGENT_BIN"), os.Getenv("ALINKSEC_UPGRADE_BROKEN_BIN")
	if !filepath.IsAbs(source) || !filepath.IsAbs(broken) {
		t.Fatal("native fixture binary paths must be absolute")
	}
	built, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	bad, err := os.ReadFile(broken)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "Upgrade Installation With Spaces")
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
	certPath := filepath.Join(work, "certs", "client.crt")
	certificate, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	certHash := sha256.Sum256(certificate)
	fixture.packages.Store("/good", built)
	fixture.packages.Store("/broken", bad)
	goodHash, badHash := sha256.Sum256(built), sha256.Sum256(bad)
	service := newUpgradeTestService(t, binary, work)
	service.start(t)
	connection := fixture.nextConnection(t)
	fixture.awaitReport(t, connection.number, func(r *pb.Report) bool { return r.GetHeartbeat() != nil })
	initialPID := service.pid(t)
	command := func(id, path, digest string) *pb.Command {
		return &pb.Command{CmdId: id, Payload: &pb.Command_AgentUpgrade{AgentUpgrade: &pb.CmdAgentUpgrade{Version: identity.AgentVersion, ExecutionContract: 1, DownloadUrl: fixture.downloadURL + path, Sha256: digest}}}
	}
	connection.commands <- command("upgrade-bad-digest", "/good", strings.Repeat("0", 64))
	fixture.awaitReport(t, connection.number, func(r *pb.Report) bool {
		return r.GetAck().GetCmdId() == "upgrade-bad-digest" && r.GetAck().GetStage() == pb.RptAck_FAILED
	})
	if service.pid(t) != initialPID {
		t.Fatal("digest failure restarted the current Agent")
	}
	connection.commands <- command("upgrade-healthy", "/good", hex.EncodeToString(goodHash[:]))
	fixture.awaitReport(t, connection.number, func(r *pb.Report) bool {
		return r.GetAck().GetCmdId() == "upgrade-healthy" && r.GetAck().GetStage() == pb.RptAck_RECEIVED
	})
	connection = fixture.nextConnection(t)
	fixture.awaitReport(t, connection.number, func(r *pb.Report) bool {
		return r.GetAck().GetCmdId() == "upgrade-healthy" && r.GetAck().GetStage() == pb.RptAck_DONE
	})
	if service.pid(t) == initialPID {
		t.Fatal("healthy upgrade did not start a new process")
	}
	t.Log("validated download, independent watchdog, new mTLS session and stabilized success")
	connection.commands <- command("upgrade-crashing", "/broken", hex.EncodeToString(badHash[:]))
	fixture.awaitReport(t, connection.number, func(r *pb.Report) bool {
		return r.GetAck().GetCmdId() == "upgrade-crashing" && r.GetAck().GetStage() == pb.RptAck_RECEIVED
	})
	deadline := time.Now().Add(25 * time.Second)
	var journal struct {
		CommandID string    `json:"command_id"`
		Phase     string    `json:"phase"`
		Deadline  time.Time `json:"deadline"`
	}
	for {
		data, _ := os.ReadFile(filepath.Join(work, "upgrade", "state.json"))
		json.Unmarshal(data, &journal)
		current, _ := os.ReadFile(binary)
		if journal.CommandID == "upgrade-crashing" && journal.Phase == "pending" && sha256.Sum256(current) == badHash {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("broken candidate was not installed: %+v", journal)
		}
		time.Sleep(100 * time.Millisecond)
	}
	service.restartWatchdog(t) // Resume the durable deadline rather than reset it.
	data, err := os.ReadFile(filepath.Join(work, "upgrade", "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var resumed struct {
		Deadline time.Time `json:"deadline"`
	}
	if err := json.Unmarshal(data, &resumed); err != nil || !resumed.Deadline.Equal(journal.Deadline) {
		t.Fatal("watchdog restart changed startup deadline")
	}
	connection = fixture.nextConnection(t)
	ack := fixture.awaitReport(t, connection.number, func(r *pb.Report) bool {
		return r.GetAck().GetCmdId() == "upgrade-crashing" && r.GetAck().GetStage() == pb.RptAck_FAILED
	}).GetAck()
	if !strings.Contains(ack.Message, "restored") {
		t.Fatalf("rollback not confirmed: %s", ack.Message)
	}
	fixture.awaitReport(t, connection.number, func(r *pb.Report) bool {
		e := r.GetSecurityEvent()
		return e.GetRuleId() == "agent-upgrade" && e.GetActionTaken() == "restored"
	})
	restored, err := os.ReadFile(binary)
	if err != nil || sha256.Sum256(restored) != goodHash {
		t.Fatal("previous Agent bytes were not restored")
	}
	cert, err := os.ReadFile(certPath)
	if err != nil || sha256.Sum256(cert) != certHash || fixture.enrollments.Load() != 1 {
		t.Fatal("upgrade/rollback changed enrollment identity")
	}
	results, err := upgrade.Outcomes(work)
	if err != nil || len(results) != 2 {
		t.Fatalf("durable results %v %v", results, err)
	}
	for _, r := range fixture.pending {
		if r.report.GetAck().GetCmdId() == "upgrade-crashing" && r.report.GetAck().GetStage() == pb.RptAck_DONE {
			t.Fatal("crashing candidate reported premature success")
		}
	}
	service.stop(t)
	service.start(t)
	connection = fixture.nextConnection(t)
	fixture.awaitReport(t, connection.number, func(r *pb.Report) bool {
		return r.GetAck().GetCmdId() == "upgrade-crashing" && r.GetAck().GetStage() == pb.RptAck_FAILED
	})
	pid := service.pid(t)
	connection.commands <- command("upgrade-crashing", "/broken", hex.EncodeToString(badHash[:]))
	fixture.awaitReport(t, connection.number, func(r *pb.Report) bool {
		return r.GetAck().GetCmdId() == "upgrade-crashing" && r.GetAck().GetStage() == pb.RptAck_FAILED
	})
	if service.pid(t) != pid {
		t.Fatal("replayed completed upgrade ran again")
	}
	t.Log("actual crashing executable rolled back after startup deadline; watchdog restart, durable failure/event replay, command deduplication and certificate identity passed")
	if evidence := os.Getenv("ALINKSEC_UPGRADE_EVIDENCE_FILE"); evidence != "" {
		data, _ := json.MarshalIndent(map[string]any{"os": runtime.GOOS, "arch": runtime.GOARCH, "success": true, "startupDeadlineSeconds": 60, "stableHeartbeatSeconds": 5, "checks": []string{"bad digest leaves service running", "healthy candidate gets final success after new authenticated session", "crashing native Go candidate automatically restored", "independent watchdog restart resumes original deadline", "failure ACK and security event survive Agent restart", "completed command does not execute again", "enrollment certificate unchanged"}}, "", "  ")
		if err := os.MkdirAll(filepath.Dir(evidence), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(evidence, append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
