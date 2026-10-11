package virusscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBaselineCacheSnapshotIsBoundedAndDoesNotReload(t *testing.T) {
	dir := t.TempDir()
	base := DBDir(dir)
	os.MkdirAll(base, 0700)
	os.WriteFile(filepath.Join(base, "manifest.json"), []byte(`{"db_version":"v1","hash_count":1,"rule_count":0}`), 0600)
	os.WriteFile(filepath.Join(base, "hashes.txt"), []byte(strings.Repeat("a", 64)+" fixture 3\n"), 0600)
	ReloadDB(dir)
	version, _, _, entries, generation, ok := CachedHashSnapshot(context.Background(), dir, 1)
	if !ok || version != "v1" || generation == 0 || len(entries) != 1 {
		t.Fatal("initial loaded cache unavailable")
	}
	os.WriteFile(filepath.Join(base, "manifest.json"), []byte(`{"db_version":"v2","hash_count":1,"rule_count":0}`), 0600)
	entries[strings.Repeat("a", 64)] = HashEntry{Name: "mutated", Severity: 5}
	v, _, _, next, g, ok := CachedHashSnapshot(context.Background(), dir, 1)
	if !ok || v != "v1" || next[strings.Repeat("a", 64)].Name != "fixture" || g != generation {
		t.Fatal("observation reloaded disk or mutated cache")
	}
	if _, _, _, _, _, ok := CachedHashSnapshot(context.Background(), dir+"other", 1); ok {
		t.Fatal("another workdir reused cache")
	}
	ReloadDB(dir)
	v, _, _, _, g, ok = CachedHashSnapshot(context.Background(), dir, 1)
	if !ok || v != "v2" || g == generation {
		t.Fatal("reload identity missing")
	}
	dbMu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	_, _, _, _, _, ok = CachedHashSnapshot(ctx, dir, 1)
	cancel()
	dbMu.Unlock()
	if ok {
		t.Fatal("cache lock ignored shared deadline")
	}
}
