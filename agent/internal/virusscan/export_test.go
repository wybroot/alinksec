package virusscan

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestQuarantineEvidenceExportIsBoundedIdentityCheckedAndNonDestructive(t *testing.T) {
	work := t.TempDir()
	path, hash := harmlessSample(t, "harmless captured evidence")
	q := NewQuarantine(work)
	id, err := q.QuarantineExpected(context.Background(), path, hash)
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []struct {
		path, id, hash string
		limit          int64
	}{
		{path, id, strings.Repeat("a", 64), 1024}, {path, id, hash, 2},
		{path, "../" + id, hash, 1024}, {path + "-other", id, hash, 1024}, {path, id, hash, 2 << 20},
	} {
		if _, err := q.ExportExpected(context.Background(), request.path, request.id, request.hash, request.limit); err == nil {
			t.Fatal("unsafe export accepted", request)
		}
	}
	for i := 0; i < 2; i++ {
		data, err := q.ExportExpected(context.Background(), path, id, hash, 1024)
		if err != nil || string(data) != "harmless captured evidence" {
			t.Fatalf("export=%q error=%v", data, err)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("export restored original")
	}
	payload := filepath.Join(q.dir, id+".payload")
	before, err := os.ReadFile(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.RestoreExpected(context.Background(), path, id, hash); err != nil {
		t.Fatal("export changed capture state", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("restored evidence differs")
	}
	if _, err := q.ExportExpected(context.Background(), path, id, hash, 1024); err == nil {
		t.Fatal("restored capture exported")
	}
}

func TestQuarantineEvidenceExportRejectsChangedBytesAndCancelledReader(t *testing.T) {
	work := t.TempDir()
	path, hash := harmlessSample(t, "harmless evidence")
	q := NewQuarantine(work)
	id, err := q.QuarantineExpected(context.Background(), path, hash)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := q.ExportExpected(ctx, path, id, hash, 1024); err == nil {
		t.Fatal("cancelled export succeeded")
	}
	payload := filepath.Join(q.dir, id+".payload")
	if err := os.Chmod(payload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(payload, []byte("modified evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := q.ExportExpected(context.Background(), path, id, hash, 1024); err == nil {
		t.Fatal("changed capture exported")
	}
}
