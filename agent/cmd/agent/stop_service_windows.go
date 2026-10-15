//go:build windows

package main

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func stopService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService("alinksec-agent")
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return err
	}
	defer s.Close()
	state, err := s.Query()
	if err != nil {
		return err
	}
	if state.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return err
		}
		until := time.Now().Add(25 * time.Second)
		for {
			state, err = s.Query()
			if err != nil {
				return err
			}
			if state.State == svc.Stopped {
				break
			}
			if time.Now().After(until) {
				return fmt.Errorf("Agent SCM service did not stop")
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	if err := s.ResetRecoveryActions(); err != nil {
		return err
	}
	return s.Delete()
}
