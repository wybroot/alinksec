//go:build !linux && !windows

package yara

import (
	"errors"
	"os"
)

func workerLimits() error                      { return errors.New("unsupported") }
func limitProcess(*os.Process) (func(), error) { return nil, errors.New("unsupported") }
func workerAllocationLimit() (uint64, error)   { return 0, errors.New("unsupported") }
