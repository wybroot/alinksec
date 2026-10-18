package securestate

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestOpenSnapshotDoesNotPreventAtomicRecordReplacement(t *testing.T) {
	dir := t.TempDir()
	if err := PrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.json")
	if err := WriteJSON(path, map[string]int{"revision": 1}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := openRecord(path)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	if err := WriteJSON(path, map[string]int{"revision": 2}); err != nil {
		t.Fatalf("open reader blocked atomic journal commit: %v", err)
	}
	var old, next map[string]int
	if err := json.NewDecoder(snapshot).Decode(&old); err != nil {
		t.Fatal(err)
	}
	if err := ReadJSON(path, &next); err != nil {
		t.Fatal(err)
	}
	if old["revision"] != 1 || next["revision"] != 2 {
		t.Fatalf("torn snapshot: old=%v next=%v", old, next)
	}
}
