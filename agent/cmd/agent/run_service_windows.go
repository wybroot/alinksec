//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows/svc"
)

func runManaged(run func(context.Context) error) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return fmt.Errorf("detect Windows service environment: %w", err)
	}
	if !isService {
		return runForeground(run)
	}
	return svc.Run("alinksec-agent", &agentService{run: run})
}

type agentService struct {
	run func(context.Context) error
}

func (s *agentService) Execute(_ []string, requests <-chan svc.ChangeRequest, statuses chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	statuses <- svc.Status{State: svc.StartPending, CheckPoint: 1, WaitHint: 15000}
	finished := make(chan error, 1)
	go func() { finished <- s.run(ctx) }()
	status := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	statuses <- status
	for {
		select {
		case err := <-finished:
			if err != nil && !(ctx.Err() != nil && errors.Is(err, context.Canceled)) {
				fmt.Fprintln(os.Stderr, "ERROR:", err)
				return true, 1
			}
			return false, 0
		case request, ok := <-requests:
			if !ok {
				requests = nil
			} else if request.Cmd == svc.Interrogate {
				statuses <- status
				continue
			} else if request.Cmd != svc.Stop && request.Cmd != svc.Shutdown {
				continue
			}
			status = svc.Status{State: svc.StopPending, CheckPoint: 1, WaitHint: 30000}
			statuses <- status
			cancel()
		}
	}
}
