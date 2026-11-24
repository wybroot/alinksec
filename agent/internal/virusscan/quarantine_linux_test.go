//go:build linux

package virusscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestBKL016LinuxStageRemovalAndReconcile(t *testing.T) {
	parentPath := t.TempDir()
	samplePath := filepath.Join(parentPath, "cross-linux.sh")
	data := []byte("#!/bin/sh\necho harmless\n")
	if err := os.WriteFile(samplePath, data, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	expected := hex.EncodeToString(sum[:])

	f, parent, err := openRegular(samplePath, true)
	if err != nil {
		t.Fatal(err)
	}
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	var recordedStage string
	rollbackFailed, err := removeCrossVolumeSource(context.Background(), parent, f, filepath.Base(samplePath), info, expected, func(stageDir string) error {
		recordedStage = stageDir
		return nil
	})
	f.Close()
	parent.Close()
	if err != nil || rollbackFailed || !stageDirPattern.MatchString(recordedStage) {
		t.Fatalf("removeCrossVolumeSource failed: rollbackFailed=%v stage=%q err=%v", rollbackFailed, recordedStage, err)
	}
	if _, err := os.Lstat(samplePath); !os.IsNotExist(err) {
		t.Fatalf("source still exists after cross-volume removal: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(parentPath, recordedStage)); !os.IsNotExist(err) {
		t.Fatalf("staging dir not removed: %v", err)
	}
}

func TestBKL016LinuxStageReplacementRollbackAndReconcileStageDir(t *testing.T) {
	// Case 1: Concurrent replacement at origPath rolls back safely without deleting new business file.
	parentPath := t.TempDir()
	samplePath := filepath.Join(parentPath, "race.sh")
	data := []byte("original bytes")
	if err := os.WriteFile(samplePath, data, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	expected := hex.EncodeToString(sum[:])

	f, parent, err := openRegular(samplePath, true)
	if err != nil {
		t.Fatal(err)
	}
	origInfo, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	rollbackFailed, err := removeCrossVolumeSource(context.Background(), parent, f, filepath.Base(samplePath), origInfo, expected, func(stageDir string) error {
		// Overwrite original path with a new inode before Renameat2 moves it.
		tmp := filepath.Join(parentPath, ".new-business")
		if werr := os.WriteFile(tmp, []byte("new business file"), 0600); werr != nil {
			return werr
		}
		return os.Rename(tmp, samplePath)
	})
	f.Close()
	parent.Close()
	if err == nil || rollbackFailed || ActionErrorCode(err) != "target_changed" {
		t.Fatalf("expected target_changed rollback, got rollbackFailed=%v err=%v", rollbackFailed, err)
	}
	got, err := os.ReadFile(samplePath)
	if err != nil || string(got) != "new business file" {
		t.Fatalf("new business file was lost: %q err=%v", got, err)
	}

	// Case 2: Reconcile staged victim completes unlink when expected digest matches,
	// or rolls back when expected is empty.
	parent2Path := t.TempDir()
	stageName := ".alinksec-quarantine-1234567890abcdef1234567890abcdef"
	stageFull := filepath.Join(parent2Path, stageName)
	if err := os.MkdirAll(stageFull, 0700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(stageFull, "victim")
	if err := os.WriteFile(victim, data, 0600); err != nil {
		t.Fatal(err)
	}
	parent2, err := openDirectory(parent2Path)
	if err != nil {
		t.Fatal(err)
	}
	defer parent2.Close()

	outcome, err := reconcileStageDir(context.Background(), parent2, "target.sh", stageName, expected)
	if err != nil || outcome != stageCompletedUnlink {
		t.Fatalf("expected stageCompletedUnlink, got %v err=%v", outcome, err)
	}
	if _, err := os.Lstat(stageFull); !os.IsNotExist(err) {
		t.Fatal("staged dir still exists")
	}

	// Re-create staged victim with empty expected -> rolls back cleanly to target.sh.
	if err := os.MkdirAll(stageFull, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(victim, []byte("rollback me"), 0600); err != nil {
		t.Fatal(err)
	}
	outcome, err = reconcileStageDir(context.Background(), parent2, "target.sh", stageName, "")
	if err != nil || outcome != stageRolledBackSource {
		t.Fatalf("expected stageRolledBackSource, got %v err=%v", outcome, err)
	}
	restored, _ := os.ReadFile(filepath.Join(parent2Path, "target.sh"))
	if string(restored) != "rollback me" {
		t.Fatalf("rolled back bytes wrong: %q", restored)
	}
}
