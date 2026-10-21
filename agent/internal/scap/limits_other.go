//go:build !linux && !windows

package scap

import (
	"errors"
	"os"
	"os/exec"
)

func nativeWorkspacePath(path string) (string, error) { return path, nil }

func workerLimits() error                      { return errors.New("unsupported") }
func configureProcess(*exec.Cmd)               {}
func limitProcess(*os.Process) (func(), error) { return nil, errors.New("unsupported") }
