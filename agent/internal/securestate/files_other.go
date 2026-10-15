//go:build !linux && !windows

package securestate

import "fmt"

func protectDirectory(string) error { return fmt.Errorf("recovery state unsupported on this system") }
func Lock(string) (func(), error) {
	return nil, fmt.Errorf("recovery state unsupported on this system")
}
func SyncDirectory(string) error   { return fmt.Errorf("recovery state unsupported on this system") }
func Replace(string, string) error { return fmt.Errorf("recovery state unsupported on this system") }
func Move(string, string) error    { return fmt.Errorf("recovery state unsupported on this system") }
