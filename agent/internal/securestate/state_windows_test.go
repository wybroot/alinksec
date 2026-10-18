//go:build windows

package securestate

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
)

// A positive control reproduces the sharing mode of the former reader.
func TestLegacyReaderReproducesWindowsReplacementSharingFailure(t *testing.T) {
	dir := t.TempDir()
	if err := PrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.json")
	if err := WriteJSON(path, map[string]int{"revision": 1}); err != nil {
		t.Fatal(err)
	}
	old, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	tmp := filepath.Join(dir, "replacement.json")
	if err := os.WriteFile(tmp, []byte(`{"revision":2}`), 0600); err != nil {
		t.Fatal(err)
	}
	err = move(tmp, path, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
	if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("legacy open did not reproduce native sharing conflict: %v", err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(path, map[string]int{"revision": 2}); err != nil {
		t.Fatal(err)
	}
}
