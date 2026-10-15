//go:build !linux && !windows

package upgrade

import "fmt"

func protectDirectory(string) error {
	return fmt.Errorf("Agent upgrade only supports Linux and Windows")
}
func lockUpgrade(string) (func(), error) {
	return nil, fmt.Errorf("Agent upgrade only supports Linux and Windows")
}
func replaceRecord(string, string) error {
	return fmt.Errorf("Agent upgrade only supports Linux and Windows")
}
func syncDirectory(string) error          { return fmt.Errorf("unsupported Agent upgrade") }
func moveExecutable(string, string) error { return fmt.Errorf("unsupported Agent upgrade") }
