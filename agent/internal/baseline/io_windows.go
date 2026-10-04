//go:build windows

package baseline

import (
	"os"
	"os/exec"
)

func openBaselineFile(path string) (*os.File, error) { return os.Open(path) }
func configureBaselineCommand(cmd *exec.Cmd)         {}
func cleanupBaselineCommand(cmd *exec.Cmd)           {}
