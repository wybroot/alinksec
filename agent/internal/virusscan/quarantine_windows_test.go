//go:build windows

package virusscan

import (
	"fmt"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func TestQuarantineWindowsErrorClassification(t *testing.T) {
	crossCases := []error{
		windows.STATUS_NOT_SAME_DEVICE,
		fmt.Errorf("wrapped: %w", windows.ERROR_NOT_SAME_DEVICE),
		syscall.EXDEV,
	}
	for _, err := range crossCases {
		if !isCrossDeviceErr(err) {
			t.Fatalf("isCrossDeviceErr(%v) = false", err)
		}
	}
	conflictCases := []error{
		windows.STATUS_OBJECT_NAME_COLLISION,
		windows.STATUS_OBJECT_NAME_EXISTS,
		windows.ERROR_ALREADY_EXISTS,
		windows.ERROR_FILE_EXISTS,
	}
	for _, err := range conflictCases {
		if !isRestoreConflictErr(err) {
			t.Fatalf("isRestoreConflictErr(%v) = false", err)
		}
	}
	inUseCases := []error{
		windows.STATUS_SHARING_VIOLATION,
		windows.STATUS_FILE_LOCK_CONFLICT,
		windows.STATUS_CANNOT_DELETE,
		windows.STATUS_DELETE_PENDING,
		windows.ERROR_SHARING_VIOLATION,
		windows.ERROR_LOCK_VIOLATION,
	}
	for _, err := range inUseCases {
		if !isFileInUseErr(err) || ActionErrorCode(err) != "file_in_use" {
			t.Fatalf("isFileInUseErr/ActionErrorCode(%v) failed", err)
		}
	}
	diskFullCases := []error{
		windows.STATUS_DISK_FULL,
		windows.ERROR_DISK_FULL,
		windows.ERROR_HANDLE_DISK_FULL,
	}
	for _, err := range diskFullCases {
		if !isDiskFullErr(err) || ActionErrorCode(err) != "insufficient_disk_space" {
			t.Fatalf("isDiskFullErr/ActionErrorCode(%v) failed", err)
		}
	}
}
