//go:build windows

package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type scmUpgradeService struct {
	manager *mgr.Mgr
	service *mgr.Service
}

func newUpgradeTestService(t *testing.T, binary, work string) upgradeTestService {
	t.Helper()
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alinksec-agent", "alinksec-agent-upgrade-watchdog"} {
		s, err := manager.OpenService(name)
		if err == nil {
			s.Close()
			manager.Disconnect()
			t.Fatalf("refusing to replace existing %s service", name)
		}
		if !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			t.Fatal(err)
		}
	}
	service, err := manager.CreateService("alinksec-agent", binary, mgr.Config{DisplayName: "ALinkSec disposable upgrade validation", StartType: mgr.StartManual}, "run", "--workdir", work)
	if err != nil {
		t.Fatal(err)
	}
	s := &scmUpgradeService{manager: manager, service: service}
	t.Cleanup(func() { retainFailedServiceCrashEvidence(t, work) })
	t.Cleanup(func() {
		if helper, err := manager.OpenService("alinksec-agent-upgrade-watchdog"); err == nil {
			cfg, err := helper.Config()
			if err == nil && strings.Contains(cfg.BinaryPathName, work) {
				helper.ResetRecoveryActions()
				helper.Control(svc.Stop)
				awaitSCMState(t, helper, svc.Stopped)
				helper.Delete()
			} else {
				t.Error("unrelated watchdog during cleanup")
			}
			helper.Close()
		}
		service.ResetRecoveryActions()
		status, _ := service.Query()
		if status.State != svc.Stopped {
			stopSCMService(t, service, status.ProcessId)
		}
		service.Delete()
		service.Close()
		manager.Disconnect()
	})
	if err := service.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: time.Second}}, 86400); err != nil {
		t.Fatal(err)
	}
	if err := service.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		t.Fatal(err)
	}
	return s
}
func (s *scmUpgradeService) start(t *testing.T) {
	if err := s.service.Start(); err != nil {
		t.Fatal(err)
	}
	awaitSCMState(t, s.service, svc.Running)
}
func (s *scmUpgradeService) stop(t *testing.T) {
	status, err := s.service.Query()
	if err != nil {
		t.Fatal(err)
	}
	stopSCMService(t, s.service, status.ProcessId)
}
func (s *scmUpgradeService) pid(t *testing.T) int {
	return int(awaitSCMState(t, s.service, svc.Running).ProcessId)
}
func (s *scmUpgradeService) restartWatchdog(t *testing.T) {
	helper, err := s.manager.OpenService("alinksec-agent-upgrade-watchdog")
	if err != nil {
		t.Fatal(err)
	}
	defer helper.Close()
	if _, err := helper.Control(svc.Stop); err != nil {
		t.Fatal(err)
	}
	awaitSCMState(t, helper, svc.Stopped)
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	awaitSCMState(t, helper, svc.Running)
}
