//go:build linux

package guard

import "syscall"

func syscallKill(pid int32) error {
	return syscall.Kill(int(pid), syscall.SIGKILL)
}
