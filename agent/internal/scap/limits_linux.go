//go:build linux

package scap

import (
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"syscall"
)

func nativeWorkspacePath(path string) (string, error) { return path, nil }
func makeNativeWorkspace() (string, error) {
	return os.MkdirTemp(nativeTempRoot(), "alinksec-scap-")
}

func workerLimits() error {
	for resource, value := range map[int]uint64{unix.RLIMIT_DATA: 256 << 20, unix.RLIMIT_CPU: 1200, unix.RLIMIT_CORE: 0, unix.RLIMIT_FSIZE: 128 << 20, unix.RLIMIT_NOFILE: 128} {
		if err := unix.Setrlimit(resource, &unix.Rlimit{Cur: value, Max: value}); err != nil {
			return err
		}
	}
	return nil
}
func configureProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}
func limitProcess(process *os.Process) (func(), error) {
	return func() { _ = syscall.Kill(-process.Pid, syscall.SIGKILL) }, nil
}
