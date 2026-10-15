//go:build windows

package isolation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type nativeManager struct{}

func withService(name string, fn func(*mgr.Service) error) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	return fn(s)
}
func (nativeManager) pid() (pid int, err error) {
	err = withService("alinksec-agent", func(s *mgr.Service) error { st, e := s.Query(); pid = int(st.ProcessId); return e })
	return
}
func (m nativeManager) verify(executable string) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !isService {
		return fmt.Errorf("host isolation requires the Windows SCM service")
	}
	pid, err := m.pid()
	if err != nil {
		return err
	}
	if pid != os.Getpid() {
		return fmt.Errorf("Agent SCM process identity changed")
	}
	return nil
}
func watchdogCommand(helper, workDir string) string {
	return strings.Join([]string{windows.EscapeArg(helper), "isolation-watchdog", "--workdir", windows.EscapeArg(workDir), "--lease", filepath.Base(filepath.Dir(helper))}, " ")
}
func (nativeManager) install(helper, workDir string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	var s *mgr.Service
	until := time.Now().Add(2 * time.Second)
	for {
		s, err = m.CreateService(serviceName, helper, mgr.Config{DisplayName: "ALinkSec host isolation recovery", StartType: mgr.StartAutomatic}, "isolation-watchdog", "--workdir", workDir, "--lease", filepath.Base(filepath.Dir(helper)))
		if !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) || time.Now().After(until) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if errors.Is(err, windows.ERROR_SERVICE_EXISTS) {
		s, err = m.OpenService(serviceName)
		if err != nil {
			return err
		}
		cfg, e := s.Config()
		if e != nil {
			s.Close()
			return e
		}
		if !strings.EqualFold(cfg.BinaryPathName, watchdogCommand(helper, workDir)) {
			s.Close()
			return fmt.Errorf("refusing an unrelated isolation watchdog service")
		}
	}
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: time.Second}}, 86400); err != nil {
		return err
	}
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return err
	}
	status, err := s.Query()
	if err != nil {
		return err
	}
	if status.State == svc.Running {
		return nil
	}
	return s.Start()
}
func (nativeManager) remove(helper, workDir string) error {
	err := withService(serviceName, func(s *mgr.Service) error {
		cfg, err := s.Config()
		if err != nil {
			return err
		}
		if !strings.EqualFold(cfg.BinaryPathName, watchdogCommand(helper, workDir)) {
			return fmt.Errorf("refusing to remove an unrelated watchdog service")
		}
		if err := s.ResetRecoveryActions(); err != nil {
			return err
		}
		return s.Delete()
	})
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) || errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return nil
	}
	return err
}

type watchdogService struct{ run func(context.Context) error }

func (s *watchdogService) Execute(_ []string, requests <-chan svc.ChangeRequest, statuses chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	statuses <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	done := make(chan error, 1)
	go func() { done <- s.run(ctx) }()
	for {
		select {
		case err := <-done:
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return true, 1
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Stop, svc.Shutdown:
				cancel()
				statuses <- svc.Status{State: svc.StopPending, WaitHint: 40000}
			case svc.Interrogate:
				statuses <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
			}
		}
	}
}
func runWatchdogService(run func(context.Context) error) error {
	managed, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !managed {
		return fmt.Errorf("watchdog must run as its dedicated SCM service")
	}
	return svc.Run(serviceName, &watchdogService{run: run})
}
