//go:build linux

package baseline

import (
	"os"
	"os/exec"
	"syscall"
)

func openBaselineFile(path string) (*os.File, error) {
	// A replaced path must not leave the Agent blocked opening a FIFO.
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

func configureBaselineCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}

func cleanupBaselineCommand(cmd *exec.Cmd) {
	if cmd.Process != nil {
		// A shell may exit before descendants close its inherited output pipes.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
