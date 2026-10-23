//go:build !windows

package comm

import (
	"os"
	"testing"
)

func assertEvidenceJournalPrivate(t *testing.T, path string) {
	t.Helper()
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("expiry lost private journal permissions", err)
	}
}
