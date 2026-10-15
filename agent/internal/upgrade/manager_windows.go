//go:build windows

package upgrade

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
	err = withService(agentServiceName, func(s *mgr.Service) error { st, e := s.Query(); pid = int(st.ProcessId); return e })
	return
}
func (m nativeManager) verify(executable string) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !isService {
		return fmt.Errorf("automatic Agent upgrade requires the Windows SCM service")
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
	return strings.Join([]string{windows.EscapeArg(helper), "upgrade-watchdog", "--workdir", windows.EscapeArg(workDir)}, " ")
}
func (nativeManager) install(helper, workDir string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.CreateService(watchdogServiceName, helper, mgr.Config{DisplayName: "ALinkSec pending upgrade recovery", StartType: mgr.StartAutomatic}, "upgrade-watchdog", "--workdir", workDir)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 5 * time.Second}}, 86400); err != nil {
		return err
	}
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return err
	}
	return s.Start()
}
func (nativeManager) remove(helper, workDir string) error {
	err := withService(watchdogServiceName, func(s *mgr.Service) error {
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
func (nativeManager) stop(executable, hash string) error {
	return withService(agentServiceName, func(s *mgr.Service) error {
		deadline := time.Now().Add(15 * time.Second)
		for {
			st, err := s.Query()
			if err != nil {
				return err
			}
			if st.State == svc.Stopped {
				return nil
			}
			if st.State != svc.StopPending {
				if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) && !errors.Is(err, windows.ERROR_SERVICE_CANNOT_ACCEPT_CTRL) {
					return err
				}
			}
			if time.Now().After(deadline) {
				if err := terminateServiceProcess(s, executable, hash); err != nil {
					return err
				}
				until := time.Now().Add(10 * time.Second)
				for {
					st, err = s.Query()
					if err != nil {
						return err
					}
					if st.State == svc.Stopped {
						return nil
					}
					if time.Now().After(until) {
						return fmt.Errorf("SCM did not observe terminated Agent")
					}
					time.Sleep(100 * time.Millisecond)
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
	})
}
func terminateServiceProcess(s *mgr.Service, executable, hash string) error {
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		return nil
	}
	if st.ProcessId == 0 {
		return fmt.Errorf("SCM cannot identify unresponsive Agent process")
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, st.ProcessId)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	buffer := make([]uint16, 32768)
	length := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(handle, 0, &buffer[0], &length); err != nil {
		return err
	}
	if !strings.EqualFold(filepath.Clean(windows.UTF16ToString(buffer[:length])), filepath.Clean(executable)) {
		return fmt.Errorf("refusing to terminate a different service executable")
	}
	if err := regularHash(executable, hash); err != nil {
		return err
	}
	current, err := s.Query()
	if err != nil {
		return err
	}
	if current.ProcessId != st.ProcessId {
		return fmt.Errorf("service process changed before termination")
	}
	if err := windows.TerminateProcess(handle, 1); err != nil {
		return err
	}
	status, err := windows.WaitForSingleObject(handle, 5000)
	if err != nil {
		return err
	}
	if status != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("terminated Agent did not exit")
	}
	return nil
}
func (nativeManager) start() error {
	return withService(agentServiceName, func(s *mgr.Service) error {
		err := s.Start()
		if errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
			return nil
		}
		return err
	})
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
	return svc.Run(watchdogServiceName, &watchdogService{run: run})
}
