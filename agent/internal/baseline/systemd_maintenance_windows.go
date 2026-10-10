//go:build windows

package baseline

import "fmt"

func readKernelClock() (kernelClockSample, error) {
	return kernelClockSample{}, fmt.Errorf("Linux内核时钟指示不可用")
}
