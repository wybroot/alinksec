package upgrade

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

const agentServiceName = "alinksec-agent"
const watchdogServiceName = "alinksec-agent-upgrade-watchdog"

type serviceManager interface {
	verify(executable string) error
	install(helper, workDir string) error
	remove(helper, workDir string) error
	pid() (int, error)
	stop(string, string) error
	start() error
}

// RunWatchdog is a private CLI entry point. The helper is a copy of the
// previously running binary, so a broken candidate cannot disable recovery.
func RunWatchdog(workDir string) error {
	tx, err := loadTransaction(workDir)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	if exe != helperPath(workDir, tx.ID) {
		return fmt.Errorf("watchdog executable does not match pending transaction")
	}
	if err := regularHash(exe, tx.OldHash); err != nil {
		return err
	}
	return runWatchdogService(func(ctx context.Context) error { return watch(ctx, workDir, nativeManager{}) })
}

// ExecutionContract is advertised by native services, never by a foreground or
// container process whose supervisor cannot be controlled for rollback.
func ExecutionContract() uint32 {
	exe, err := os.Executable()
	if err != nil {
		return 0
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return 0
	}
	if err := (nativeManager{}).verify(exe); err != nil {
		return 0
	}
	return 1
}
