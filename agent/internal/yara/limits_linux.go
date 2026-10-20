//go:build linux

package yara

import (
	"golang.org/x/sys/unix"
	"os"
)

func workerLimits() error {
	// Linux >=4.7 accounts private anonymous mappings against RLIMIT_DATA.
	// This bounds native allocations as well as Go's writable heap; virtual
	// address reservations are intentionally not treated as resident memory.
	if err := unix.Setrlimit(unix.RLIMIT_DATA, &unix.Rlimit{Cur: 192 << 20, Max: 192 << 20}); err != nil {
		return err
	}
	if err := unix.Setrlimit(unix.RLIMIT_CPU, &unix.Rlimit{Cur: 30, Max: 30}); err != nil {
		return err
	}
	return unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{})
}
func limitProcess(p *os.Process) (func(), error) { return func() {}, nil }
func workerAllocationLimit() (uint64, error) {
	var limit unix.Rlimit
	err := unix.Getrlimit(unix.RLIMIT_DATA, &limit)
	return limit.Cur, err
}
