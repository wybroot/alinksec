package virusscan

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func TestRealtimeRootsPreserveMissingDirectories(t *testing.T) {
	if runtime.GOOS == "windows" {
		missing := filepath.Join(t.TempDir(), "not-created")
		t.Setenv("TEMP", missing)
		t.Setenv("TMP", missing)
		if !slices.Contains(RealtimeRoots(), missing) {
			t.Fatal("missing realtime root discarded")
		}
		if slices.Contains(QuickScanRoots(), missing) {
			t.Fatal("explicit quick scan scope changed")
		}
	} else {
		if !slices.Contains(RealtimeRoots(), "/var/spool/cron") {
			t.Fatal("declared default root missing")
		}
	}
	for _, p := range QuickScanRoots() {
		if _, err := os.Stat(p); err != nil {
			t.Fatal("quick scan selected absent root", p)
		}
	}
}
