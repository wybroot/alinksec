//go:build windows

package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

func TestServiceStopAndShutdown(t *testing.T) {
	for name, command := range map[string]svc.Cmd{"stop": svc.Stop, "shutdown": svc.Shutdown} {
		t.Run(name, func(t *testing.T) {
			requests := make(chan svc.ChangeRequest, 2)
			statuses := make(chan svc.Status, 8)
			finished := make(chan uint32, 1)
			service := &agentService{run: func(ctx context.Context) error {
				<-ctx.Done()
				return ctx.Err()
			}}
			go func() {
				specific, code := service.Execute(nil, requests, statuses)
				if specific {
					code = 99
				}
				finished <- code
			}()
			awaitStatus(t, statuses, svc.StartPending)
			running := awaitStatus(t, statuses, svc.Running)
			if running.Accepts != svc.AcceptStop|svc.AcceptShutdown {
				t.Fatalf("accepted controls: %v", running.Accepts)
			}
			requests <- svc.ChangeRequest{Cmd: svc.Interrogate}
			awaitStatus(t, statuses, svc.Running)
			requests <- svc.ChangeRequest{Cmd: command}
			awaitStatus(t, statuses, svc.StopPending)
			select {
			case code := <-finished:
				if code != 0 {
					t.Fatalf("normal stop exit code: %d", code)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("service did not cancel Agent")
			}
		})
	}
}

func TestServiceReportsAgentFailure(t *testing.T) {
	statuses := make(chan svc.Status, 8)
	service := &agentService{run: func(context.Context) error { return errors.New("invalid configuration") }}
	specific, code := service.Execute(nil, make(chan svc.ChangeRequest), statuses)
	if !specific || code == 0 {
		t.Fatalf("failure reported as success: specific=%v code=%d", specific, code)
	}
}

func awaitStatus(t *testing.T, statuses <-chan svc.Status, want svc.State) svc.Status {
	t.Helper()
	select {
	case status := <-statuses:
		if status.State != want {
			t.Fatalf("state = %v, want %v", status.State, want)
		}
		return status
	case <-time.After(3 * time.Second):
		t.Fatalf("timeout waiting for state %v", want)
		return svc.Status{}
	}
}
