//go:build !windows

package main

import "context"

func runManaged(run func(context.Context) error) error {
	return runForeground(run)
}
