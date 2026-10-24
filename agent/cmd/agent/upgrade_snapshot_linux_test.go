//go:build linux

package main

import "os"

func openUpgradeSnapshot(path string) (*os.File, error) { return os.Open(path) }
