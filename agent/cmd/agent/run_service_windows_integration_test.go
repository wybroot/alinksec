//go:build windows

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"github.com/alinksec/alinksec-agent/internal/config"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"gopkg.in/yaml.v3"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestNativeWindowsService(t *testing.T) {
	if os.Getenv("ALINKSEC_SMOKE_ALLOW_FIXTURES") != "true" {
		t.Skip("requires an explicitly authorized disposable Windows host")
	}
	source := os.Getenv("ALINKSEC_SMOKE_AGENT_BIN")
	if !filepath.IsAbs(source) {
		t.Fatal("ALINKSEC_SMOKE_AGENT_BIN must be the absolute path to the built Agent exe")
	}
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Disconnect()
	if existing, err := manager.OpenService("alinksec-agent"); err == nil {
		existing.Close()
		t.Fatal("refusing to replace an existing alinksec-agent service")
	} else if !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		t.Fatal(err)
	}

	root := filepath.Join(t.TempDir(), "Agent Installation With Spaces")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "alinksec-agent.exe")
	built, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, built, 0700); err != nil {
		t.Fatal(err)
	}
	fixture, address, caFile := newSCMFixture(t, root)
	work := filepath.Join(root, "Agent Work Directory")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, binary, "install", "--server", address,
		"--token", "ENROLL-windows-scm-fixture", "--ca-file", caFile, "--workdir", work).CombinedOutput()
	if err != nil {
		t.Fatalf("native install: %v\n%s", err, output)
	}
	cfgPath := filepath.Join(work, "agent.yml")
	cfg, err := config.Load(cfgPath)
	if err != nil || cfg.EnrollToken != "" {
		t.Fatalf("installed configuration or cleared enrollment token: %v", err)
	}
	disabled := false
	cfg.Decoy = config.DecoyConfig{Enabled: &disabled, Response: "alert_only"}
	cfg.HeartbeatInterval = time.Second
	cfg.CollectInterval = 24 * time.Hour
	contents, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	applyNativeConfig(t, binary, work, contents)
	certPath := filepath.Join(work, "certs", "client.crt")
	certificate, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	identity := sha256.Sum256(certificate)
	service, err := manager.CreateService("alinksec-agent", binary,
		mgr.Config{DisplayName: "ALinkSec native service validation", StartType: mgr.StartManual},
		"run", "--workdir", work)
	if err != nil {
		t.Fatal(err)
	}
	// Remove recovery first so failed checks cannot leave a restarting service.
	defer func() {
		current, _ := service.Query()
		pid := current.ProcessId
		if err := service.ResetRecoveryActions(); err != nil {
			t.Errorf("reset recovery during cleanup: %v", err)
		}
		service.Control(svc.Stop)
		deadline := time.Now().Add(30 * time.Second)
		for {
			current, err := service.Query()
			if current.ProcessId != 0 {
				pid = current.ProcessId
			}
			if err != nil || current.State == svc.Stopped {
				break
			}
			if time.Now().After(deadline) {
				t.Error("service did not stop during cleanup")
				break
			}
			service.Control(svc.Stop)
			time.Sleep(200 * time.Millisecond)
		}
		if pid != 0 {
			waitSCMProcess(t, pid)
		}
		if err := service.Delete(); err != nil {
			t.Errorf("delete validation service: %v", err)
		}
		service.Close()
	}()
	if err := service.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: time.Second}}, 86400); err != nil {
		t.Fatal(err)
	}
	if err := service.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		t.Fatal(err)
	}
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	first := awaitSCMState(t, service, svc.Running)
	connection := fixture.nextConnection(t)
	fixture.awaitReport(t, connection.number, func(report *pb.Report) bool { return report.GetHeartbeat() != nil })
	initial := fixture.awaitReport(t, connection.number, func(report *pb.Report) bool { return report.GetAsset() != nil }).GetAsset()
	if len(initial.GetSoftware()) == 0 || len(initial.GetProcesses()) == 0 || len(initial.GetAccounts()) == 0 {
		t.Fatal("native Windows host assets were empty")
	}
	t.Logf("SCM RUNNING with real mTLS and assets: software=%d processes=%d accounts=%d", len(initial.GetSoftware()), len(initial.GetProcesses()), len(initial.GetAccounts()))
	if interrogated, err := service.Control(svc.Interrogate); err != nil || interrogated.State != svc.Running {
		t.Fatalf("SCM interrogation: status=%+v error=%v", interrogated, err)
	}
	connection.commands <- &pb.Command{CmdId: "scm-collect", Payload: &pb.Command_CollectNow{CollectNow: &pb.CmdCollectNow{CollectorNames: []string{"software"}}}}
	fixture.awaitReport(t, connection.number, func(report *pb.Report) bool {
		return report.GetAsset() != nil && len(report.GetAsset().GetSoftware()) > 0
	})
	fixture.awaitReport(t, connection.number, func(report *pb.Report) bool {
		return report.GetAck().GetCmdId() == "scm-collect" && report.GetAck().GetStage() == pb.RptAck_DONE
	})
	stopSCMService(t, service, first.ProcessId)
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	second := awaitSCMState(t, service, svc.Running)
	connection = fixture.nextConnection(t)
	fixture.awaitReport(t, connection.number, func(report *pb.Report) bool { return report.GetHeartbeat() != nil })
	if second.ProcessId == first.ProcessId {
		t.Fatal("SCM stop/start did not create a new Agent process")
	}
	connection.commands <- &pb.Command{CmdId: "scm-restart", Payload: &pb.Command_AgentControl{AgentControl: &pb.CmdAgentControl{Action: pb.CmdAgentControl_RESTART}}}
	fixture.awaitReport(t, connection.number, func(report *pb.Report) bool {
		return report.GetAck().GetCmdId() == "scm-restart" && report.GetAck().GetStage() == pb.RptAck_DONE
	})
	connection = fixture.nextConnection(t)
	fixture.awaitReport(t, connection.number, func(report *pb.Report) bool { return report.GetHeartbeat() != nil })
	recovered := awaitSCMState(t, service, svc.Running)
	if recovered.ProcessId == second.ProcessId {
		t.Fatal("SCM recovery did not replace the exiting Agent")
	}
	restored, err := os.ReadFile(certPath)
	if err != nil || sha256.Sum256(restored) != identity || fixture.enrollments.Load() != 1 {
		t.Fatalf("restart changed enrollment identity: error=%v enrollments=%d", err, fixture.enrollments.Load())
	}
	stopSCMService(t, service, recovered.ProcessId)
	time.Sleep(2500 * time.Millisecond)
	awaitSCMState(t, service, svc.Stopped)
	if fixture.sessionCount.Load() != 3 {
		t.Fatalf("unexpected sessions after explicit stop: %d", fixture.sessionCount.Load())
	}
	t.Log("SCM stop/start, successful-exit recovery, stable identity and explicit-stop behavior passed")
}

func awaitSCMState(t *testing.T, service *mgr.Service, want svc.State) svc.Status {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		current, err := service.Query()
		if err != nil {
			t.Fatal(err)
		}
		if current.State == want && (want != svc.Running || current.ProcessId != 0) {
			return current
		}
		if time.Now().After(deadline) {
			t.Fatalf("SCM state=%+v, want %v", current, want)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func stopSCMService(t *testing.T, service *mgr.Service, pid uint32) {
	t.Helper()
	if _, err := service.Control(svc.Stop); err != nil {
		t.Fatal(err)
	}
	stopped := awaitSCMState(t, service, svc.Stopped)
	if stopped.Win32ExitCode != 0 || stopped.ServiceSpecificExitCode != 0 {
		t.Fatalf("normal SCM stop reported failure: %+v", stopped)
	}
	waitSCMProcess(t, pid)
}

func waitSCMProcess(t *testing.T, pid uint32) {
	t.Helper()
	process, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return
	}
	if err != nil {
		t.Error(err)
		return
	}
	defer windows.CloseHandle(process)
	if result, err := windows.WaitForSingleObject(process, 10000); err != nil || result != windows.WAIT_OBJECT_0 {
		t.Errorf("Agent process did not exit after SCM stop: result=%v error=%v", result, err)
	}
}
