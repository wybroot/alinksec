//go:build windows

package main

import (
	"golang.org/x/sys/windows"
	"os"
)

func openUpgradeSnapshot(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "snapshot", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}
