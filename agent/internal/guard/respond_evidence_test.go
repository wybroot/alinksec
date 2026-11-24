package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDumpEvidenceEnforcesFileCountDirectoryAndSizeBudgets(t *testing.T) {
	oldFiles, oldDirBytes, oldFileBytes := guardEvidenceMaxFiles, guardEvidenceMaxDirBytes, guardEvidenceMaxFileBytes
	t.Cleanup(func() {
		guardEvidenceMaxFiles = oldFiles
		guardEvidenceMaxDirBytes = oldDirBytes
		guardEvidenceMaxFileBytes = oldFileBytes
	})

	work := t.TempDir()
	g := &Guard{workDir: work}

	// Enforce per-file cap: drop full process list when serialized JSON exceeds limit.
	guardEvidenceMaxFileBytes = 256
	keys := g.dumpEvidence("decoy_tamper", &suspectProc{Pid: 42, Exe: "/tmp/suspect"}, []string{"/tmp/a"})
	if len(keys) != 1 {
		t.Fatalf("unexpected evidence keys: %v", keys)
	}
	data, err := os.ReadFile(filepath.Join(work, filepath.FromSlash(keys[0])))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "processes_omitted") || !strings.Contains(string(data), "/tmp/suspect") {
		t.Fatalf("expected truncated dump to omit process list while keeping suspect lineage: %s", string(data))
	}

	// Enforce file count limit across repeated dumps even within same millisecond.
	guardEvidenceMaxFileBytes = defaultGuardEvidenceFileBytes
	guardEvidenceMaxFiles = 3
	guardEvidenceMaxDirBytes = 32 << 20
	for i := 0; i < 6; i++ {
		time.Sleep(2 * time.Millisecond)
		if ks := g.dumpEvidence("ransom_behavior", nil, []string{"/tmp/f"}); len(ks) != 1 {
			t.Fatalf("dump %d failed: %v", i, ks)
		}
	}
	entries, err := os.ReadDir(filepath.Join(work, "evidence"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected evidence directory capped at 3 files, got %d", len(entries))
	}

	// Enforce total directory byte cap.
	guardEvidenceMaxFiles = 100
	guardEvidenceMaxDirBytes = int64(len(data)) + 200
	if ks := g.dumpEvidence("decoy_tamper", nil, []string{"/tmp/latest"}); len(ks) != 1 {
		t.Fatal(ks)
	}
	entries, err = os.ReadDir(filepath.Join(work, "evidence"))
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		total += info.Size()
	}
	if total > guardEvidenceMaxDirBytes {
		t.Fatalf("evidence dir exceeded byte cap: total=%d cap=%d", total, guardEvidenceMaxDirBytes)
	}
}
