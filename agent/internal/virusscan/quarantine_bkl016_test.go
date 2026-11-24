package virusscan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var errTestCrossDevice = errors.New("simulated cross-device link")

func newPortableQuarantine(t *testing.T, workDir string) *quarantine {
	t.Helper()
	q := NewQuarantine(workDir)
	q.minFreeBytes = 1024
	q.freeSpace = func(string) (uint64, error) { return 1 << 30, nil }
	q.openQuarantineDir = func() (*os.File, error) {
		if err := os.MkdirAll(q.dir, 0700); err != nil {
			return nil, err
		}
		return os.Open(q.dir)
	}
	ops := defaultQuarantineOps()
	ops.openDirectory = func(path string) (*os.File, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		st, serr := f.Stat()
		if serr != nil || !st.IsDir() {
			f.Close()
			return nil, fmt.Errorf("not a directory")
		}
		return f, nil
	}
	ops.openRegular = func(path string, mutation bool) (*os.File, *os.File, error) {
		parent, err := ops.openDirectory(filepath.Dir(path))
		if err != nil {
			return nil, nil, err
		}
		f, err := os.Open(path)
		if err != nil {
			parent.Close()
			return nil, nil, err
		}
		st, serr := f.Stat()
		if serr != nil || !st.Mode().IsRegular() {
			f.Close()
			parent.Close()
			return nil, nil, fmt.Errorf("not a regular file")
		}
		return f, parent, nil
	}
	ops.openAt = func(parent *os.File, name string, create bool) (*os.File, error) {
		p := filepath.Join(parent.Name(), name)
		if create {
			return os.OpenFile(p, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		}
		return os.Open(p)
	}
	ops.openMutatingAt = func(parent *os.File, name string) (*os.File, error) {
		return os.Open(filepath.Join(parent.Name(), name))
	}
	ops.removeAt = func(parent *os.File, name string) error {
		return os.Remove(filepath.Join(parent.Name(), name))
	}
	ops.renamePinned = func(from, file *os.File, name string, to *os.File, newName string) error {
		// Force EXDEV for files under separate-volume test dirs or allow same-volume rename.
		if file != nil {
			_ = file.Close()
		}
		dst := filepath.Join(to.Name(), newName)
		if _, err := os.Lstat(dst); err == nil {
			return os.ErrExist
		}
		return os.Rename(filepath.Join(from.Name(), name), dst)
	}
	ops.originalSecurity = func(*os.File) (string, error) { return "portable-sec", nil }
	ops.restoreCopy = func(ctx context.Context, src, parent *os.File, name string, mode os.FileMode, uid, gid int, security string) error {
		dst := filepath.Join(parent.Name(), name)
		if _, err := os.Lstat(dst); err == nil {
			return fmt.Errorf("%w: destination exists", errRestoreConflict)
		}
		temp := filepath.Join(parent.Name(), ".restore-tmp-"+randomID())
		out, err := os.OpenFile(temp, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		if _, err := src.Seek(0, io.SeekStart); err != nil {
			out.Close()
			_ = os.Remove(temp)
			return err
		}
		if err := copyBounded(ctx, out, src, maxFileSize); err != nil {
			out.Close()
			_ = os.Remove(temp)
			return err
		}
		_ = out.Sync()
		out.Close()
		if _, err := os.Lstat(dst); err == nil {
			_ = os.Remove(temp)
			return fmt.Errorf("%w: destination occupied", errRestoreConflict)
		}
		return os.Rename(temp, dst)
	}
	ops.syncDir = func(*os.File) error { return nil }
	ops.chmodPayload = func(string) error { return nil }
	ops.isCrossDeviceErr = func(err error) bool { return errors.Is(err, errTestCrossDevice) }
	ops.removeCrossVolume = func(ctx context.Context, parent, file *os.File, base string, origInfo os.FileInfo, expected string, onStage func(stageDir string) error) (bool, error) {
		stageName := ".alinksec-quarantine-" + randomID()
		stagePath := filepath.Join(parent.Name(), stageName)
		if err := os.Mkdir(stagePath, 0700); err != nil {
			return false, err
		}
		if onStage != nil {
			if err := onStage(stageName); err != nil {
				_ = os.Remove(stagePath)
				return false, err
			}
		}
		origPath := filepath.Join(parent.Name(), base)
		currentInfo, err := os.Lstat(origPath)
		if err != nil || !os.SameFile(origInfo, currentInfo) {
			_ = file.Close()
			_ = os.Remove(stagePath)
			return false, fmt.Errorf("%w: original path replaced before isolation", errTargetChanged)
		}
		got, err := openedDigest(ctx, file)
		_ = file.Close()
		if err != nil || got != expected {
			_ = os.Remove(stagePath)
			return false, fmt.Errorf("%w: target modified before isolation", errTargetChanged)
		}
		victimPath := filepath.Join(stagePath, "victim")
		if err := os.Rename(origPath, victimPath); err != nil {
			_ = os.Remove(stagePath)
			return false, err
		}
		movedInfo, err := os.Lstat(victimPath)
		if err != nil || !os.SameFile(origInfo, movedInfo) {
			rbErr := os.Rename(victimPath, origPath)
			if rbErr == nil {
				_ = os.Remove(stagePath)
				return false, fmt.Errorf("%w: original path replaced", errTargetChanged)
			}
			return true, fmt.Errorf("%w: rollback collision: %v", errQuarantineIncomplete, rbErr)
		}
		if err := os.Remove(victimPath); err != nil {
			return true, fmt.Errorf("%w: %v", errQuarantineIncomplete, err)
		}
		_ = os.Remove(stagePath)
		return false, nil
	}
	ops.reconcileStage = func(ctx context.Context, parent *os.File, base, stageName, expected string) (stageOutcome, error) {
		stagePath := filepath.Join(parent.Name(), stageName)
		if _, err := os.Lstat(stagePath); os.IsNotExist(err) {
			return stageAbsent, nil
		}
		victimPath := filepath.Join(stagePath, "victim")
		vf, err := os.Open(victimPath)
		if err != nil {
			if os.IsNotExist(err) {
				_ = os.Remove(stagePath)
				return stageCleanedEmpty, nil
			}
			return stageRollbackConflict, err
		}
		if expected != "" {
			got, derr := openedDigest(ctx, vf)
			vf.Close()
			if derr == nil && got == expected {
				if rerr := os.Remove(victimPath); rerr != nil {
					return stageRollbackConflict, rerr
				}
				_ = os.Remove(stagePath)
				return stageCompletedUnlink, nil
			}
		} else {
			vf.Close()
		}
		origPath := filepath.Join(parent.Name(), base)
		if _, err := os.Lstat(origPath); err == nil {
			return stageRollbackConflict, nil
		}
		if err := os.Rename(victimPath, origPath); err == nil {
			_ = os.Remove(stagePath)
			return stageRolledBackSource, nil
		}
		return stageRollbackConflict, nil
	}
	q.ops = ops
	return q
}

func writeFixtureFile(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func readMetaJSON(t *testing.T, dir, id string) quarantineMeta {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, id+".meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m quarantineMeta
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestBKL016CrossVolumeQuarantineRestoreExportAndDelete(t *testing.T) {
	work := t.TempDir()
	q := newPortableQuarantine(t, work)
	q.ops.renamePinned = func(*os.File, *os.File, string, *os.File, string) error {
		return fmt.Errorf("move across mounts: %w", errTestCrossDevice)
	}

	srcDir := t.TempDir()
	samplePath := filepath.Join(srcDir, "cross.bin")
	digest := writeFixtureFile(t, samplePath, "cross-volume harmless sample payload")

	id, err := q.QuarantineExpected(context.Background(), samplePath, digest)
	if err != nil || !objectID.MatchString(id) {
		t.Fatalf("cross-volume quarantine failed: id=%q err=%v", id, err)
	}
	if _, err := os.Stat(samplePath); !os.IsNotExist(err) {
		t.Fatalf("original cross-volume file still exists: %v", err)
	}
	meta := readMetaJSON(t, q.dir, id)
	if meta.State != "active" || meta.TransferMode != "cross_volume" || meta.StageDir != "" {
		t.Fatalf("unexpected meta after cross-volume quarantine: %+v", meta)
	}
	exported, err := q.ExportExpected(context.Background(), samplePath, id, digest, 1<<20)
	if err != nil || string(exported) != "cross-volume harmless sample payload" {
		t.Fatalf("export failed: %q err=%v", exported, err)
	}

	// Occupied destination must refuse restore and preserve replacement file.
	writeFixtureFile(t, samplePath, "new replacement business file")
	err = q.RestoreExpected(context.Background(), samplePath, id, digest)
	if ActionErrorCode(err) != "restore_target_occupied" {
		t.Fatalf("expected restore_target_occupied, got code=%q err=%v", ActionErrorCode(err), err)
	}
	got, _ := os.ReadFile(samplePath)
	if string(got) != "new replacement business file" {
		t.Fatalf("occupied restore overwrote replacement: %q", got)
	}

	// Free destination allows clean restore.
	if err := os.Remove(samplePath); err != nil {
		t.Fatal(err)
	}
	if err := q.RestoreExpected(context.Background(), samplePath, id, digest); err != nil {
		t.Fatalf("clean restore failed: %v", err)
	}
	got, _ = os.ReadFile(samplePath)
	if string(got) != "cross-volume harmless sample payload" {
		t.Fatalf("restored bytes mismatch: %q", got)
	}
	if _, err := os.Stat(filepath.Join(q.dir, id+".payload")); !os.IsNotExist(err) {
		t.Fatalf("restored payload was not removed: %v", err)
	}
	if readMetaJSON(t, q.dir, id).State != "restored" {
		t.Fatal("expected restored state")
	}

	// Cross-volume direct delete without prior quarantine ID captures and deletes safely.
	delID, err := q.DeleteExpectedWithID(context.Background(), samplePath, "", digest)
	if err != nil || !objectID.MatchString(delID) {
		t.Fatalf("cross-volume delete failed: id=%q err=%v", delID, err)
	}
	if _, err := os.Stat(samplePath); !os.IsNotExist(err) {
		t.Fatalf("deleted cross-volume original still exists: %v", err)
	}
	if readMetaJSON(t, q.dir, delID).State != "deleted" {
		t.Fatal("expected deleted state")
	}
}

func TestBKL016CrossVolumeReplacementRacePreservesNewBusinessFile(t *testing.T) {
	work := t.TempDir()
	q := newPortableQuarantine(t, work)
	q.ops.renamePinned = func(*os.File, *os.File, string, *os.File, string) error {
		return errTestCrossDevice
	}

	srcDir := t.TempDir()
	samplePath := filepath.Join(srcDir, "target.bin")
	digest := writeFixtureFile(t, samplePath, "original malicious bytes")

	origRemove := q.ops.removeCrossVolume
	q.ops.removeCrossVolume = func(ctx context.Context, parent, file *os.File, base string, origInfo os.FileInfo, expected string, onStage func(stageDir string) error) (bool, error) {
		// Simulate an unrelated business file replacing original path right after Phase A copy.
		_ = file.Close()
		_ = os.Remove(samplePath)
		writeFixtureFile(t, samplePath, "unrelated replacement business file")
		return origRemove(ctx, parent, file, base, origInfo, expected, onStage)
	}

	id, err := q.QuarantineExpected(context.Background(), samplePath, digest)
	if err == nil || id != "" || ActionErrorCode(err) != "target_changed" {
		t.Fatalf("expected clean target_changed abort, got id=%q code=%q err=%v", id, ActionErrorCode(err), err)
	}
	got, err := os.ReadFile(samplePath)
	if err != nil || string(got) != "unrelated replacement business file" {
		t.Fatalf("replacement business file was lost or corrupted: %q err=%v", got, err)
	}
	entries, _ := os.ReadDir(q.dir)
	if len(entries) != 0 {
		t.Fatalf("aborted cross-volume capture left residue in %s: %v", q.dir, entries)
	}
}

func TestBKL016CrossVolumeOpenHandleAndConcurrentWriterFailSafely(t *testing.T) {
	t.Run("concurrent_writer_aborts_without_quarantine", func(t *testing.T) {
		work := t.TempDir()
		q := newPortableQuarantine(t, work)
		q.ops.renamePinned = func(*os.File, *os.File, string, *os.File, string) error {
			return errTestCrossDevice
		}
		samplePath := filepath.Join(t.TempDir(), "writer.bin")
		digest := writeFixtureFile(t, samplePath, "initial malware bytes")

		origRemove := q.ops.removeCrossVolume
		q.ops.removeCrossVolume = func(ctx context.Context, parent, file *os.File, base string, origInfo os.FileInfo, expected string, onStage func(stageDir string) error) (bool, error) {
			if err := os.WriteFile(samplePath, []byte("mutated concurrent payload"), 0600); err != nil {
				t.Fatal(err)
			}
			return origRemove(ctx, parent, file, base, origInfo, expected, onStage)
		}
		id, err := q.QuarantineExpected(context.Background(), samplePath, digest)
		if err == nil || id != "" || ActionErrorCode(err) != "target_changed" {
			t.Fatalf("expected target_changed, got id=%q code=%q err=%v", id, ActionErrorCode(err), err)
		}
		got, _ := os.ReadFile(samplePath)
		if string(got) != "mutated concurrent payload" {
			t.Fatalf("mutated file unexpectedly removed: %q", got)
		}
	})

	t.Run("locked_or_in_use_handle_never_claims_quarantined", func(t *testing.T) {
		work := t.TempDir()
		q := newPortableQuarantine(t, work)
		q.ops.renamePinned = func(*os.File, *os.File, string, *os.File, string) error {
			return errTestCrossDevice
		}
		q.ops.removeCrossVolume = func(ctx context.Context, parent, file *os.File, base string, origInfo os.FileInfo, expected string, onStage func(stageDir string) error) (bool, error) {
			return false, fmt.Errorf("%w: sharing violation", errFileInUse)
		}
		samplePath := filepath.Join(t.TempDir(), "locked.exe")
		digest := writeFixtureFile(t, samplePath, "locked executable bytes")

		id, err := q.QuarantineExpected(context.Background(), samplePath, digest)
		if err == nil || id != "" || ActionErrorCode(err) != "file_in_use" {
			t.Fatalf("expected file_in_use, got id=%q code=%q err=%v", id, ActionErrorCode(err), err)
		}
		if _, err := os.Stat(samplePath); err != nil {
			t.Fatalf("original locked file must remain untouched: %v", err)
		}
	})
}

func TestBKL016InsufficientDiskSpaceRejectsBeforeMutatingOriginal(t *testing.T) {
	work := t.TempDir()
	q := newPortableQuarantine(t, work)
	q.minFreeBytes = 32 << 20
	q.freeSpace = func(string) (uint64, error) { return 8 << 20, nil }

	samplePath := filepath.Join(t.TempDir(), "big.bin")
	digest := writeFixtureFile(t, samplePath, "sample bytes")

	id, err := q.QuarantineExpected(context.Background(), samplePath, digest)
	if err == nil || id != "" || ActionErrorCode(err) != "insufficient_disk_space" {
		t.Fatalf("expected insufficient_disk_space, got id=%q code=%q err=%v", id, ActionErrorCode(err), err)
	}
	if _, err := os.Stat(samplePath); err != nil {
		t.Fatalf("original was touched despite low disk space: %v", err)
	}
	entries, _ := os.ReadDir(q.dir)
	if len(entries) != 0 {
		t.Fatalf("unexpected quarantine metadata on disk-full abort: %v", entries)
	}
}

func TestBKL016RestoreParentChangedAndDeletePreservesReplacement(t *testing.T) {
	work := t.TempDir()
	q := newPortableQuarantine(t, work)
	q.ops.renamePinned = func(*os.File, *os.File, string, *os.File, string) error {
		return errTestCrossDevice
	}

	parentDir := filepath.Join(t.TempDir(), "origparent")
	samplePath := filepath.Join(parentDir, "sample.sh")
	digest := writeFixtureFile(t, samplePath, "parent replacement fixture")

	id, err := q.QuarantineExpected(context.Background(), samplePath, digest)
	if err != nil {
		t.Fatal(err)
	}
	// Replace original parent directory with a different directory inode/file index.
	movedDir := parentDir + "-moved"
	if err := os.Rename(parentDir, movedDir); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(movedDir)
	if err := os.MkdirAll(parentDir, 0700); err != nil {
		t.Fatal(err)
	}
	err = q.RestoreExpected(context.Background(), samplePath, id, digest)
	if ActionErrorCode(err) != "parent_directory_changed" {
		t.Fatalf("expected parent_directory_changed, got code=%q err=%v", ActionErrorCode(err), err)
	}

	// Restore parent back, write unrelated replacement at samplePath, then delete ID.
	_ = os.RemoveAll(parentDir)
	if err := os.Rename(movedDir, parentDir); err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, samplePath, "unrelated file after detection")
	if _, err := q.DeleteExpectedWithID(context.Background(), samplePath, id, digest); err != nil {
		t.Fatalf("DeleteExpectedWithID failed: %v", err)
	}
	got, _ := os.ReadFile(samplePath)
	if string(got) != "unrelated file after detection" {
		t.Fatalf("delete altered unrelated file: %q", got)
	}
}

func TestBKL016ReconcileHandlesAllCrashStatesIdempotently(t *testing.T) {
	work := t.TempDir()
	q := newPortableQuarantine(t, work)
	if err := os.MkdirAll(q.dir, 0700); err != nil {
		t.Fatal(err)
	}

	dirHandle, err := os.Open(q.dir)
	if err != nil {
		t.Fatal(err)
	}
	pid := q.ops.parentIdentity(dirHandle)
	dirHandle.Close()
	_ = pid

	mkMeta := func(id, origPath, hash, state, mode, stage string) *quarantineMeta {
		pdir, err := q.ops.openDirectory(filepath.Dir(origPath))
		if err != nil {
			t.Fatal(err)
		}
		parentID := q.ops.parentIdentity(pdir)
		pdir.Close()
		info, _ := os.Stat(origPath)
		var size int64 = 16
		if info != nil {
			size = info.Size()
		}
		return &quarantineMeta{
			ID:           id,
			OrigPath:     origPath,
			QuarFile:     filepath.Join(q.dir, id+".payload"),
			Sha256:       hash,
			Size:         size,
			QuarAt:       time.Now().Unix(),
			Mode:         0600,
			UID:          -1,
			GID:          -1,
			ParentID:     parentID,
			State:        state,
			TransferMode: mode,
			StageDir:     stage,
		}
	}
	saveMeta := func(m *quarantineMeta) {
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(q.dir, m.ID+".meta.json"), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	savePayload := func(id, content string) {
		if err := os.WriteFile(filepath.Join(q.dir, id+".payload"), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}

	// 1. Orphan temp files cleaned safely.
	orphan1 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.meta.tmp-123"
	orphan2 := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.capture-456"
	_ = os.WriteFile(filepath.Join(q.dir, orphan1), []byte("tmp"), 0600)
	_ = os.WriteFile(filepath.Join(q.dir, orphan2), []byte("cap"), 0600)

	// 2. Prepared with no payload and stage rolled back.
	idNoBody := "11111111111111111111111111111111"
	pNoBody := filepath.Join(t.TempDir(), "nob.bin")
	hNoBody := writeFixtureFile(t, pNoBody, "still here")
	saveMeta(mkMeta(idNoBody, pNoBody, hNoBody, "prepared", "cross_volume", ""))

	// 3. Cross-volume Phase A crash (prepared + valid payload + matching original untouched).
	idPhaseA := "22222222222222222222222222222222"
	pPhaseA := filepath.Join(t.TempDir(), "phasea.bin")
	hPhaseA := writeFixtureFile(t, pPhaseA, "cross volume phase A")
	savePayload(idPhaseA, "cross volume phase A")
	saveMeta(mkMeta(idPhaseA, pPhaseA, hPhaseA, "prepared", "cross_volume", ""))

	// 4. Prepared with valid payload and original gone -> promote to active.
	idPromoteGone := "33333333333333333333333333333333"
	dirGone := t.TempDir()
	pGone := filepath.Join(dirGone, "gone.bin")
	hGone := writeFixtureFile(t, pGone, "already removed original")
	mGone := mkMeta(idPromoteGone, pGone, hGone, "prepared", "cross_volume", "")
	_ = os.Remove(pGone)
	savePayload(idPromoteGone, "already removed original")
	saveMeta(mGone)

	// 5. Prepared with valid payload and unrelated replacement occupying origPath -> promote without touching replacement!
	idPromoteReplace := "44444444444444444444444444444444"
	pReplace := filepath.Join(t.TempDir(), "replaced.bin")
	hOrigReplace := writeFixtureFile(t, pReplace, "malicious version")
	mReplace := mkMeta(idPromoteReplace, pReplace, hOrigReplace, "prepared", "cross_volume", "")
	writeFixtureFile(t, pReplace, "clean new replacement file")
	savePayload(idPromoteReplace, "malicious version")
	saveMeta(mReplace)

	// 6. Prepared with staged victim dir still present and valid payload -> unlink stage victim and promote active.
	idStaged := "55555555555555555555555555555555"
	stageHostDir := t.TempDir()
	pStaged := filepath.Join(stageHostDir, "staged.bin")
	hStaged := writeFixtureFile(t, pStaged, "staged crash bytes")
	stageName := ".alinksec-quarantine-55555555555555555555555555555555"
	mStaged := mkMeta(idStaged, pStaged, hStaged, "prepared", "cross_volume", stageName)
	_ = os.MkdirAll(filepath.Join(stageHostDir, stageName), 0700)
	_ = os.Rename(pStaged, filepath.Join(stageHostDir, stageName, "victim"))
	savePayload(idStaged, "staged crash bytes")
	saveMeta(mStaged)

	// 7. Deleting state left mid-delete -> complete delete atomically.
	idDeleting := "66666666666666666666666666666666"
	pDeleting := filepath.Join(t.TempDir(), "del.bin")
	hDeleting := writeFixtureFile(t, pDeleting, "deleting bytes")
	mDeleting := mkMeta(idDeleting, pDeleting, hDeleting, "deleting", "same_volume", "")
	_ = os.Remove(pDeleting)
	savePayload(idDeleting, "deleting bytes")
	saveMeta(mDeleting)

	// 8. Restored state with leftover payload -> remove orphan payload body only.
	idRestored := "77777777777777777777777777777777"
	pRestored := filepath.Join(t.TempDir(), "rest.bin")
	hRestored := writeFixtureFile(t, pRestored, "restored bytes")
	savePayload(idRestored, "restored bytes")
	saveMeta(mkMeta(idRestored, pRestored, hRestored, "restored", "same_volume", ""))

	// 9. Active state with corrupted payload -> mark review_required without deleting!
	idCorruptActive := "88888888888888888888888888888888"
	pCorrupt := filepath.Join(t.TempDir(), "corrupt.bin")
	hCorrupt := writeFixtureFile(t, pCorrupt, "expected bytes")
	savePayload(idCorruptActive, "tampered bytes")
	saveMeta(mkMeta(idCorruptActive, pCorrupt, hCorrupt, "active", "same_volume", ""))

	// 10. Corrupt JSON metadata & orphan payload -> flagged review_required, never deleted.
	idBadJSON := "99999999999999999999999999999999"
	_ = os.WriteFile(filepath.Join(q.dir, idBadJSON+".meta.json"), []byte("{not json"), 0600)
	idOrphanPayload := "abcdefabcdefabcdefabcdefabcdefab"
	savePayload(idOrphanPayload, "orphan payload kept")

	rep, err := q.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	if rep.CleanedOrphanTemp != 2 || rep.RolledBackPrepared != 2 || rep.PromotedActive != 3 ||
		rep.CompletedDeletes != 1 || rep.CleanedTerminalBody != 2 || rep.CleanedStageDirs != 1 ||
		rep.ActiveObjects != 3 || rep.ReviewRequired != 3 || rep.CorruptMeta != 1 {
		t.Fatalf("unexpected ReconcileReport: %+v", rep)
	}

	// Verify exact filesystem outcomes.
	for _, orphan := range []string{orphan1, orphan2, idNoBody + ".meta.json", idPhaseA + ".meta.json", idPhaseA + ".payload", idDeleting + ".payload", idRestored + ".payload"} {
		if _, err := os.Stat(filepath.Join(q.dir, orphan)); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be cleaned", orphan)
		}
	}
	if _, err := os.Stat(pPhaseA); err != nil {
		t.Fatalf("Phase A original must remain on disk: %v", err)
	}
	if got, _ := os.ReadFile(pReplace); string(got) != "clean new replacement file" {
		t.Fatalf("replacement file damaged by reconcile: %q", got)
	}
	if _, err := os.Stat(filepath.Join(stageHostDir, stageName)); !os.IsNotExist(err) {
		t.Fatal("staged dir was not cleaned")
	}
	for _, promoted := range []string{idPromoteGone, idPromoteReplace, idStaged} {
		if m := readMetaJSON(t, q.dir, promoted); m.State != "active" || m.StageDir != "" {
			t.Fatalf("expected promoted active state for %s, got %+v", promoted, m)
		}
	}
	if m := readMetaJSON(t, q.dir, idDeleting); m.State != "deleted" {
		t.Fatalf("expected deleted state, got %+v", m)
	}
	if m := readMetaJSON(t, q.dir, idCorruptActive); m.State != "review_required" || m.ReviewReason != "active_payload_missing_or_corrupt" {
		t.Fatalf("expected review_required for corrupt active, got %+v", m)
	}
	if _, err := q.ExportExpected(context.Background(), pCorrupt, idCorruptActive, hCorrupt, 1<<20); err == nil {
		t.Fatal("review_required object must not be exported")
	}
	if _, err := os.Stat(filepath.Join(q.dir, idOrphanPayload+".payload")); err != nil {
		t.Fatal("orphan payload must be preserved for review")
	}
	if _, err := os.Stat(filepath.Join(q.dir, idBadJSON+".meta.json")); err != nil {
		t.Fatal("corrupt metadata must be preserved for review")
	}

	// Idempotency check on second pass.
	rep2, err := q.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep2.PromotedActive != 0 || rep2.RolledBackPrepared != 0 || rep2.CompletedDeletes != 0 ||
		rep2.CleanedOrphanTemp != 0 || rep2.CleanedTerminalBody != 0 || rep2.CleanedStageDirs != 0 ||
		rep2.ActiveObjects != 3 || rep2.ReviewRequired != 3 || rep2.CorruptMeta != 1 {
		t.Fatalf("second Reconcile pass was not idempotent: %+v", rep2)
	}
}

func TestActionErrorCodeClassification(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, ""},
		{errScanBudget, "budget_exhausted"},
		{context.DeadlineExceeded, "budget_exhausted"},
		{errInsufficientSpace, "insufficient_disk_space"},
		{errFileInUse, "file_in_use"},
		{errRestoreConflict, "restore_target_occupied"},
		{errParentChanged, "parent_directory_changed"},
		{errTargetChanged, "target_changed"},
		{errQuarantineIncomplete, "quarantine_incomplete"},
		{errQuarantineCorrupt, "quarantine_integrity_failed"},
		{bytes.ErrTooLarge, "file_identity_or_io_failure"},
	}
	for _, tc := range cases {
		if got := ActionErrorCode(tc.err); got != tc.want {
			t.Fatalf("ActionErrorCode(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
	if strings.Contains(ActionErrorCode(errQuarantineIncomplete), " ") {
		t.Fatal("action code must not contain whitespace")
	}
}
