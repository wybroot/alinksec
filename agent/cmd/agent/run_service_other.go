//go:build !windows

package main

import "context"

func runManaged(_ string, run func(context.Context) error) error {
	return runForeground(run)
}
