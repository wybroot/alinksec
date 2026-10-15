//go:build !linux && !windows

package upgrade

import (
	"context"
	"fmt"
)

type nativeManager struct{}

func (nativeManager) verify(string) error { return fmt.Errorf("unsupported upgrade service manager") }
func (nativeManager) install(string, string) error {
	return fmt.Errorf("unsupported upgrade service manager")
}
func (nativeManager) remove(string, string) error {
	return fmt.Errorf("unsupported upgrade service manager")
}
func (nativeManager) pid() (int, error) { return 0, fmt.Errorf("unsupported upgrade service manager") }
func (nativeManager) stop(string, string) error {
	return fmt.Errorf("unsupported upgrade service manager")
}
func (nativeManager) start() error { return fmt.Errorf("unsupported upgrade service manager") }
func runWatchdogService(func(context.Context) error) error {
	return fmt.Errorf("unsupported upgrade service manager")
}
