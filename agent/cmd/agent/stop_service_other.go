//go:build !linux && !windows

package main

import "fmt"

func stopService() error {
	return fmt.Errorf("native service uninstall is unsupported on this platform")
}
