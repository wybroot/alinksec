//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/alinksec/alinksec-agent/internal/securestate"

	"golang.org/x/sys/windows/svc"
)

func runManaged(work string, run func(context.Context) error) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return fmt.Errorf("detect Windows service environment: %w", err)
	}
	if !isService {
		return runForeground(run)
	}
	if err := retainServiceCrashOutput(work); err != nil {
		return fmt.Errorf("prepare private service crash output: %w", err)
	}
	return svc.Run("alinksec-agent", &agentService{run: run})
}

// SCM does not supply a usable stderr. Keep runtime panics in a private folder
// so an unexpected 1067 stop retains its cause. Keep only three process records;
// normal application reports and configuration contents are not written here.
func retainServiceCrashOutput(work string) error {
	dir := filepath.Join(work, "service-crashes")
	if err := securestate.PrivateDir(dir); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var old []os.DirEntry
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "crash-") && entry.Type().IsRegular() {
			old = append(old, entry)
		}
	}
	sort.Slice(old, func(i, j int) bool {
		a, ae := old[i].Info()
		b, be := old[j].Info()
		return ae == nil && (be != nil || a.ModTime().After(b.ModTime()))
	})
	for _, entry := range old[min(2, len(old)):] {
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
			return err
		}
	}
	f, err := os.CreateTemp(dir, "crash-*.log")
	if err != nil {
		return err
	}
	defer f.Close()
	return debug.SetCrashOutput(f, debug.CrashOptions{})
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
