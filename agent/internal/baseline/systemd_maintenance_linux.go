//go:build linux

package baseline

import "golang.org/x/sys/unix"

func readKernelClock() (kernelClockSample, error) {
	// Modes is always zero. No clock setting, discipline changes or CAP_SYS_TIME.
	value := unix.Timex{}
	state, err := unix.Adjtimex(&value)
	return kernelClockSample{state, uint32(value.Status), value.Maxerror, value.Esterror}, err
}
