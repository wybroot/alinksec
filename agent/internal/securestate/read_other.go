//go:build !windows

package securestate

import "os"

func openRecord(path string) (*os.File, error) { return os.Open(path) }
