package virusscan

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/shirou/gopsutil/v4/disk"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

var quarantineGate = make(chan struct{}, 1)

func lockQuarantine(ctx context.Context) error {
	select {
	case quarantineGate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return errScanBudget
	}
}
func unlockQuarantine() { <-quarantineGate }

const defaultMinQuarantineFreeBytes uint64 = 32 << 20

var (
	objectID        = regexp.MustCompile(`^[0-9a-f]{32}$`)
	digestID        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	stageDirPattern = regexp.MustCompile(`^\.alinksec-quarantine-[0-9a-f]{32}$`)

	errInsufficientSpace    = errors.New("insufficient disk space")
	errFileInUse            = errors.New("file in use or locked")
	errRestoreConflict      = errors.New("restore target already exists")
	errParentChanged        = errors.New("original parent changed")
	errTargetChanged        = errors.New("target identity or bytes changed")
	errQuarantineIncomplete = errors.New("quarantine incomplete")
	errQuarantineCorrupt    = errors.New("quarantine payload corrupt or missing")
)

type stageOutcome int

const (
	stageAbsent stageOutcome = iota
	stageCleanedEmpty
	stageCompletedUnlink
	stageRolledBackSource
	stageRollbackConflict
)

// ReconcileReport summarizes post-crash quarantine reconciliation outcomes using
// strictly numeric counters so diagnostic bundles never leak host paths.
type ReconcileReport struct {
	ScannedObjects      int `json:"scanned_objects"`
	ActiveObjects       int `json:"active_objects"`
	PromotedActive      int `json:"promoted_active"`
	RolledBackPrepared  int `json:"rolled_back_prepared"`
	CompletedDeletes    int `json:"completed_deletes"`
	CleanedOrphanTemp   int `json:"cleaned_orphan_temp"`
	CleanedTerminalBody int `json:"cleaned_terminal_body"`
	CleanedStageDirs    int `json:"cleaned_stage_dirs"`
	ReviewRequired      int `json:"review_required"`
	CorruptMeta         int `json:"corrupt_meta"`
}

type quarantineOps struct {
	openDirectory     func(path string) (*os.File, error)
	openRegular       func(path string, mutation bool) (*os.File, *os.File, error)
	openAt            func(parent *os.File, name string, create bool) (*os.File, error)
	openMutatingAt    func(parent *os.File, name string) (*os.File, error)
	removeAt          func(parent *os.File, name string) error
	renamePinned      func(from, file *os.File, name string, to *os.File, newName string) error
	renameLocal       func(dir *os.File, oldName, newName string) error
	parentIdentity    func(parent *os.File) string
	originalSecurity  func(file *os.File) (string, error)
	restoreCopy       func(ctx context.Context, src, parent *os.File, name string, mode os.FileMode, uid, gid int, security string) error
	syncDir           func(dir *os.File) error
	removeCrossVolume func(ctx context.Context, parent, file *os.File, base string, origInfo os.FileInfo, expected string, onStage func(stageDir string) error) (bool, error)
	reconcileStage    func(ctx context.Context, parent *os.File, base, stageName, expected string) (stageOutcome, error)
	isCrossDeviceErr  func(err error) bool
	isFileInUseErr    func(err error) bool
	isRestoreConflict func(err error) bool
	isDiskFullErr     func(err error) bool
	chmodPayload      func(path string) error
}

func defaultQuarantineOps() quarantineOps {
	return quarantineOps{
		openDirectory:    openDirectory,
		openRegular:      openRegular,
		openAt:           openAt,
		openMutatingAt:   openMutatingAt,
		removeAt:         removeAt,
		renamePinned:     renamePinned,
		renameLocal:      func(dir *os.File, oldName, newName string) error { return os.Rename(filepath.Join(dir.Name(), oldName), filepath.Join(dir.Name(), newName)) },
		parentIdentity:   parentIdentity,
		originalSecurity: originalSecurity,
		restoreCopy:      restoreCopy,
		syncDir:          syncDir,
		removeCrossVolume: removeCrossVolumeSource,
		reconcileStage:   reconcileStageDir,
		isCrossDeviceErr: isCrossDeviceErr,
		isFileInUseErr:   isFileInUseErr,
		isRestoreConflict: isRestoreConflictErr,
		isDiskFullErr:    isDiskFullErr,
		chmodPayload: func(path string) error {
			if runtime.GOOS == "windows" {
				return nil
			}
			return os.Chmod(path, 0400)
		},
	}
}

func defaultFreeSpace(path string) (uint64, error) {
	u, err := disk.Usage(path)
	if err != nil {
		return 0, err
	}
	return u.Free, nil
}

type quarantine struct {
	dir               string
	workDir           string
	minFreeBytes      uint64
	freeSpace         func(path string) (uint64, error)
	openQuarantineDir func() (*os.File, error)
	ops               quarantineOps
}
type quarantineMeta struct {
	ID           string `json:"id"`
	OrigPath     string `json:"orig_path"`
	QuarFile     string `json:"quar_file"`
	Sha256       string `json:"sha256"`
	Size         int64  `json:"size"`
	QuarAt       int64  `json:"quar_at"`
	Mode         uint32 `json:"mode"`
	UID          int    `json:"uid"`
	GID          int    `json:"gid"`
	ParentID     string `json:"parent_id"`
	State        string `json:"state"`
	Security     string `json:"security"`
	TransferMode string `json:"transfer_mode,omitempty"`
	StageDir     string `json:"stage_dir,omitempty"`
	ReviewReason string `json:"review_reason,omitempty"`
}

func NewQuarantine(workDir string) *quarantine {
	return &quarantine{
		dir:          QuarantineDir(workDir),
		workDir:      workDir,
		minFreeBytes: defaultMinQuarantineFreeBytes,
		freeSpace:    defaultFreeSpace,
		ops:          defaultQuarantineOps(),
	}
}
func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

// ActionErrorCode maps quarantine/file operation errors to stable structured codes
// reported to the server and UI (never misreporting failures as success).
func ActionErrorCode(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, errScanBudget) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "budget_exhausted"
	}
	if errors.Is(err, errInsufficientSpace) || isDiskFullErr(err) {
		return "insufficient_disk_space"
	}
	if errors.Is(err, errFileInUse) || isFileInUseErr(err) {
		return "file_in_use"
	}
	if errors.Is(err, errRestoreConflict) || isRestoreConflictErr(err) {
		return "restore_target_occupied"
	}
	if errors.Is(err, errParentChanged) {
		return "parent_directory_changed"
	}
	if errors.Is(err, errTargetChanged) {
		return "target_changed"
	}
	if errors.Is(err, errQuarantineIncomplete) {
		return "quarantine_incomplete"
	}
	if errors.Is(err, errQuarantineCorrupt) {
		return "quarantine_integrity_failed"
	}
	return "file_identity_or_io_failure"
}
func actionErrorCode(err error) string {
	return ActionErrorCode(err)
}
func copyBounded(ctx context.Context, out io.Writer, in io.Reader, limit int64) error {
	b := make([]byte, 64<<10)
	var count int64
	for {
		if ctx.Err() != nil {
			return errScanBudget
		}
		n, err := in.Read(b)
		count += int64(n)
		if count > limit {
			return errScanBudget
		}
		if n > 0 {
			written, e := out.Write(b[:n])
			if e != nil {
				return e
			}
			if written != n {
				return io.ErrShortWrite
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
func openedDigest(ctx context.Context, f *os.File) (string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() > maxFileSize {
		return "", fmt.Errorf("invalid regular file")
	}
	h := sha256.New()
	if err := copyBounded(ctx, h, f, maxFileSize); err != nil {
		return "", err
	}
	after, err := f.Stat()
	if err != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return "", fmt.Errorf("file changed")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func (q *quarantine) directory() (*os.File, error) {
	if err := os.MkdirAll(q.dir, 0700); err != nil {
		return nil, err
	}
	if err := secureAgentState(q.workDir, filepath.Dir(q.dir), q.dir); err != nil {
		return nil, err
	}
	st, err := os.Lstat(q.dir)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("unsafe quarantine directory")
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("quarantine is not private")
	}
	if runtime.GOOS != "windows" {
		for _, path := range []string{q.workDir, filepath.Dir(q.dir), q.dir} {
			st, err := os.Stat(path)
			if err != nil {
				return nil, err
			}
			uid, _ := originalOwner(st)
			if uid != os.Geteuid() || st.Mode().Perm()&0022 != 0 {
				return nil, fmt.Errorf("unsafe Agent state owner or permissions")
			}
		}
	}
	return openDirectory(q.dir)
}

func (q *quarantine) openQDir() (*os.File, error) {
	if q.openQuarantineDir != nil {
		return q.openQuarantineDir()
	}
	return q.directory()
}

func (q *quarantine) checkFreeSpace(dirPath string, size int64) error {
	if size < 0 {
		return fmt.Errorf("invalid target size")
	}
	if q.freeSpace == nil {
		return nil
	}
	avail, err := q.freeSpace(dirPath)
	if err != nil {
		if q.ops.isDiskFullErr != nil && q.ops.isDiskFullErr(err) {
			return fmt.Errorf("%w: %v", errInsufficientSpace, err)
		}
		return nil
	}
	need := uint64(size)
	if need > math.MaxUint64-q.minFreeBytes {
		return fmt.Errorf("%w: file size overflows free-space check", errInsufficientSpace)
	}
	need += q.minFreeBytes
	if avail < need {
		return fmt.Errorf("%w: require %d bytes, available %d bytes", errInsufficientSpace, need, avail)
	}
	return nil
}

func writeMeta(ops quarantineOps, dir *os.File, m *quarantineMeta, create bool) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	name := m.ID + ".meta.json"
	if !create {
		name = m.ID + ".meta.tmp-" + randomID()
	}
	f, err := ops.openAt(dir, name, true)
	if err != nil {
		if ops.isDiskFullErr != nil && ops.isDiskFullErr(err) {
			return fmt.Errorf("%w: %v", errInsufficientSpace, err)
		}
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	f.Close()
	if err != nil {
		_ = ops.removeAt(dir, name)
		if ops.isDiskFullErr != nil && ops.isDiskFullErr(err) {
			return fmt.Errorf("%w: %v", errInsufficientSpace, err)
		}
		return err
	}
	if !create {
		// Private directory: metadata replacement cannot be influenced by ordinary
		// users. Payload identities are verified again before every action.
		if err = ops.renameLocal(dir, name, m.ID+".meta.json"); err != nil {
			_ = ops.removeAt(dir, name)
			return err
		}
	}
	_ = ops.syncDir(dir)
	return nil
}

func copyAndVerifyTemp(ctx context.Context, ops quarantineOps, dir, src *os.File, origInfo os.FileInfo, expected, temp string, checkOrigin bool) error {
	out, err := ops.openAt(dir, temp, true)
	if err != nil {
		if ops.isDiskFullErr != nil && ops.isDiskFullErr(err) {
			return fmt.Errorf("%w: %v", errInsufficientSpace, err)
		}
		return err
	}
	_, err = src.Seek(0, io.SeekStart)
	if err == nil {
		err = copyBounded(ctx, out, src, maxFileSize)
	}
	if err == nil {
		var copied string
		copied, err = openedDigest(ctx, out)
		if err == nil && copied != expected {
			err = fmt.Errorf("%w: captured bytes changed", errTargetChanged)
		}
	}
	if err == nil && checkOrigin && origInfo != nil {
		after, statErr := src.Stat()
		if statErr != nil || !os.SameFile(origInfo, after) || after.Size() != origInfo.Size() || !after.ModTime().Equal(origInfo.ModTime()) {
			err = fmt.Errorf("%w: target modified during capture", errTargetChanged)
		}
	}
	if err == nil {
		err = out.Sync()
	}
	_ = out.Close()
	if err != nil {
		_ = ops.removeAt(dir, temp)
		if ops.isDiskFullErr != nil && ops.isDiskFullErr(err) {
			return fmt.Errorf("%w: %v", errInsufficientSpace, err)
		}
		return err
	}
	return nil
}

func (q *quarantine) QuarantineExpected(ctx context.Context, path, expected string) (string, error) {
	if err := lockQuarantine(ctx); err != nil {
		return "", err
	}
	defer unlockQuarantine()
	expected = strings.ToLower(expected)
	if !digestID.MatchString(expected) || !filepath.IsAbs(path) || protectedPath(path, q.workDir) {
		return "", fmt.Errorf("invalid target identity")
	}
	f, parent, err := q.ops.openRegular(path, true)
	if err != nil {
		if q.ops.isFileInUseErr(err) {
			return "", fmt.Errorf("%w: %v", errFileInUse, err)
		}
		return "", err
	}
	defer f.Close()
	defer parent.Close()
	if protectedPath(filepath.Join(parent.Name(), filepath.Base(path)), q.workDir) {
		return "", fmt.Errorf("resolved target is protected Agent state")
	}
	got, err := openedDigest(ctx, f)
	if err != nil || got != expected {
		return "", fmt.Errorf("%w: target bytes differ from detection", errTargetChanged)
	}
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	dir, err := q.openQDir()
	if err != nil {
		return "", err
	}
	defer dir.Close()
	if err := q.checkFreeSpace(dir.Name(), info.Size()); err != nil {
		return "", err
	}
	uid, gid := originalOwner(info)
	security, err := q.ops.originalSecurity(f)
	if err != nil {
		return "", err
	}
	id := randomID()
	m := &quarantineMeta{
		ID: id, OrigPath: filepath.Clean(path), QuarFile: filepath.Join(q.dir, id+".payload"),
		Sha256: expected, Size: info.Size(), QuarAt: time.Now().Unix(), Mode: uint32(info.Mode().Perm()),
		UID: uid, GID: gid, ParentID: q.ops.parentIdentity(parent), State: "prepared",
		Security: security, TransferMode: "same_volume",
	}
	if m.ParentID == "" {
		return "", fmt.Errorf("parent identity unavailable")
	}
	if err := writeMeta(q.ops, dir, m, true); err != nil {
		return "", err
	}
	name := id + ".payload"
	err = q.ops.renamePinned(parent, f, filepath.Base(path), dir, name)
	if err != nil && q.ops.isCrossDeviceErr(err) {
		return q.quarantineCrossVolume(ctx, dir, parent, f, path, expected, info, m)
	}
	if err != nil {
		_ = q.ops.removeAt(dir, id+".meta.json")
		if q.ops.isFileInUseErr(err) {
			return "", fmt.Errorf("%w: %v", errFileInUse, err)
		}
		if q.ops.isDiskFullErr(err) {
			return "", fmt.Errorf("%w: %v", errInsufficientSpace, err)
		}
		return "", err
	}
	got, err = openedDigest(ctx, f)
	if err == nil && got != expected {
		err = fmt.Errorf("%w: moved bytes differ from detection", errTargetChanged)
	}
	// Copy into a new Agent-owned inode: writers holding the original descriptor
	// cannot alter the stored sample after capture. Publish only matching bytes.
	if err == nil {
		temp := id + ".capture-" + randomID()
		e := copyAndVerifyTemp(ctx, q.ops, dir, f, info, expected, temp, false)
		if e == nil {
			// Windows cannot replace the captured destination while this source
			// descriptor remains open. The verified new inode is ready to publish.
			e = f.Close()
		}
		if e == nil {
			if e = q.ops.renameLocal(dir, temp, name); e != nil {
				_ = q.ops.removeAt(dir, temp)
			}
		}
		if e != nil {
			err = e
		}
	}
	if err != nil {
		// On a changed/failed capture after same-volume move, roll back only if
		// the original name remains vacant. Never unlink unrecovered evidence.
		rollbackErr := fmt.Errorf("rollback open failed")
		if moved, e := q.ops.openMutatingAt(dir, name); e == nil {
			rollbackErr = q.ops.renamePinned(dir, moved, name, parent, filepath.Base(path))
			moved.Close()
		}
		if rollbackErr != nil {
			m.State = "review_required"
			m.ReviewReason = "same_volume_rollback_failed"
			_ = writeMeta(q.ops, dir, m, false)
			return id, fmt.Errorf("%w: retained object %s", errQuarantineIncomplete, id)
		}
		_ = q.ops.removeAt(dir, id+".meta.json")
		_ = q.ops.syncDir(dir)
		_ = q.ops.syncDir(parent)
		return "", err
	}
	if err := q.ops.chmodPayload(filepath.Join(dir.Name(), name)); err != nil {
		m.State = "review_required"
		m.ReviewReason = "payload_permission_failed"
		_ = writeMeta(q.ops, dir, m, false)
		return id, fmt.Errorf("%w: %v", errQuarantineIncomplete, err)
	}
	_ = q.ops.syncDir(dir)
	m.State = "active"
	if err := writeMeta(q.ops, dir, m, false); err != nil {
		return id, fmt.Errorf("%w: payload retained with prepared metadata: %s", errQuarantineIncomplete, id)
	}
	return id, nil
}

// quarantineCrossVolume implements 3-phase crash-safe cross-volume isolation:
// Phase A copies & verifies payload under prepared state before touching the
// source; Phase B stages/removes original under identity & digest checks;
// Phase C commits active metadata.
func (q *quarantine) quarantineCrossVolume(ctx context.Context, dir, parent, f *os.File, path, expected string, info os.FileInfo, m *quarantineMeta) (string, error) {
	id := m.ID
	name := id + ".payload"
	temp := id + ".capture-" + randomID()
	if err := q.checkFreeSpace(dir.Name(), info.Size()); err != nil {
		_ = q.ops.removeAt(dir, id+".meta.json")
		return "", err
	}
	if err := copyAndVerifyTemp(ctx, q.ops, dir, f, info, expected, temp, true); err != nil {
		_ = q.ops.removeAt(dir, id+".meta.json")
		return "", err
	}
	if err := q.ops.renameLocal(dir, temp, name); err != nil {
		_ = q.ops.removeAt(dir, temp)
		_ = q.ops.removeAt(dir, id+".meta.json")
		return "", err
	}
	if err := q.ops.chmodPayload(filepath.Join(dir.Name(), name)); err != nil {
		_ = q.ops.removeAt(dir, name)
		_ = q.ops.removeAt(dir, id+".meta.json")
		return "", err
	}
	_ = q.ops.syncDir(dir)
	m.TransferMode = "cross_volume"
	if err := writeMeta(q.ops, dir, m, false); err != nil {
		_ = q.ops.removeAt(dir, name)
		_ = q.ops.removeAt(dir, id+".meta.json")
		return "", err
	}
	rollbackFailed, rerr := q.ops.removeCrossVolume(ctx, parent, f, filepath.Base(path), info, expected, func(stageDir string) error {
		m.StageDir = stageDir
		return writeMeta(q.ops, dir, m, false)
	})
	if rerr != nil {
		if rollbackFailed {
			m.State = "review_required"
			m.ReviewReason = "cross_volume_stage_rollback_conflict"
			_ = writeMeta(q.ops, dir, m, false)
			return id, fmt.Errorf("%w: retained object %s: %v", errQuarantineIncomplete, id, rerr)
		}
		_ = q.ops.removeAt(dir, name)
		_ = q.ops.removeAt(dir, id+".meta.json")
		_ = q.ops.syncDir(dir)
		return "", rerr
	}
	m.StageDir = ""
	m.State = "active"
	if err := writeMeta(q.ops, dir, m, false); err != nil {
		return id, fmt.Errorf("%w: payload retained with prepared metadata: %s", errQuarantineIncomplete, id)
	}
	return id, nil
}

func (q *quarantine) readMetaStrict(dir *os.File, id string) (*quarantineMeta, error) {
	if !objectID.MatchString(id) {
		return nil, fmt.Errorf("missing object identity")
	}
	f, err := q.ops.openAt(dir, id+".meta.json", false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(data) > 65536 {
		return nil, fmt.Errorf("invalid metadata")
	}
	var m quarantineMeta
	if json.Unmarshal(data, &m) != nil || m.ID != id || !filepath.IsAbs(m.OrigPath) || !digestID.MatchString(strings.ToLower(m.Sha256)) || m.QuarFile != filepath.Join(q.dir, id+".payload") || m.ParentID == "" || m.Size < 0 || m.Size > maxFileSize {
		return nil, fmt.Errorf("quarantine identity mismatch")
	}
	m.Sha256 = strings.ToLower(m.Sha256)
	return &m, nil
}

func (q *quarantine) loadMeta(dir *os.File, path, id, expected string) (*quarantineMeta, error) {
	return q.loadMetaForAction(dir, path, id, expected, false)
}

func (q *quarantine) loadMetaForAction(dir *os.File, path, id, expected string, allowDeleting bool) (*quarantineMeta, error) {
	if !objectID.MatchString(id) || !digestID.MatchString(strings.ToLower(expected)) || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("missing object identity")
	}
	m, err := q.readMetaStrict(dir, id)
	if err != nil {
		return nil, err
	}
	if pathKey(m.OrigPath) != pathKey(path) || m.Sha256 != strings.ToLower(expected) {
		return nil, fmt.Errorf("quarantine identity mismatch")
	}
	switch m.State {
	case "active", "prepared", "review_required":
		return m, nil
	case "deleting":
		if allowDeleting {
			return m, nil
		}
	}
	return nil, fmt.Errorf("quarantine identity mismatch")
}

func (q *quarantine) RestoreExpected(ctx context.Context, path, id, expected string) error {
	if err := lockQuarantine(ctx); err != nil {
		return err
	}
	defer unlockQuarantine()
	dir, err := q.openQDir()
	if err != nil {
		return err
	}
	defer dir.Close()
	m, err := q.loadMeta(dir, path, id, expected)
	if err != nil {
		return err
	}
	f, err := q.ops.openAt(dir, id+".payload", false)
	if err != nil {
		return fmt.Errorf("%w: %v", errQuarantineCorrupt, err)
	}
	fClosed := false
	defer func() {
		if !fClosed {
			_ = f.Close()
		}
	}()
	got, err := openedDigest(ctx, f)
	if err != nil || got != m.Sha256 {
		return fmt.Errorf("%w: quarantine bytes changed", errQuarantineCorrupt)
	}
	parent, err := q.ops.openDirectory(filepath.Dir(m.OrigPath))
	if err != nil {
		return err
	}
	defer parent.Close()
	if q.ops.parentIdentity(parent) != m.ParentID {
		return fmt.Errorf("%w: recovery requires manual review", errParentChanged)
	}
	if err := q.ops.restoreCopy(ctx, f, parent, filepath.Base(m.OrigPath), os.FileMode(m.Mode), m.UID, m.GID, m.Security); err != nil {
		if q.ops.isRestoreConflict(err) {
			return fmt.Errorf("%w: %v", errRestoreConflict, err)
		}
		if q.ops.isDiskFullErr(err) {
			return fmt.Errorf("%w: %v", errInsufficientSpace, err)
		}
		return err
	}
	fClosed = true
	_ = f.Close()
	// Successful copy leaves evidence until metadata records the real outcome.
	m.State = "restored"
	m.StageDir = ""
	m.ReviewReason = ""
	if err := writeMeta(q.ops, dir, m, false); err != nil {
		return err
	}
	if err := q.ops.removeAt(dir, id+".payload"); err != nil {
		return err
	}
	_ = q.ops.syncDir(dir)
	return nil
}

// ExportExpected reads an immutable capture through the same pinned native
// handles as restore/delete. It neither restores nor changes quarantine state.
func (q *quarantine) ExportExpected(ctx context.Context, path, id, expected string, limit int64) ([]byte, error) {
	if limit <= 0 || limit > 1<<20 {
		return nil, fmt.Errorf("invalid evidence limit")
	}
	if err := lockQuarantine(ctx); err != nil {
		return nil, err
	}
	defer unlockQuarantine()
	dir, err := q.openQDir()
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	m, err := q.loadMeta(dir, path, id, expected)
	if err != nil {
		return nil, err
	}
	if m.State != "active" || m.Size > limit {
		return nil, fmt.Errorf("capture unavailable or exceeds evidence limit")
	}
	f, err := q.ops.openAt(dir, id+".payload", false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() != m.Size {
		return nil, fmt.Errorf("capture metadata changed")
	}
	var data bytes.Buffer
	if err := copyBounded(ctx, &data, f, limit); err != nil {
		return nil, err
	}
	after, err := f.Stat()
	sum := sha256.Sum256(data.Bytes())
	if err != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || int64(data.Len()) != m.Size || hex.EncodeToString(sum[:]) != m.Sha256 {
		return nil, fmt.Errorf("capture bytes changed")
	}
	return data.Bytes(), nil
}
func (q *quarantine) DeleteExpected(ctx context.Context, path, id, expected string) error {
	_, err := q.DeleteExpectedWithID(ctx, path, id, expected)
	return err
}

// Keep a capture ID in failed receipts so an incomplete delete remains recoverable.
func (q *quarantine) DeleteExpectedWithID(ctx context.Context, path, id, expected string) (string, error) {
	if id == "" {
		captured, err := q.QuarantineExpected(ctx, path, expected)
		if err != nil {
			return captured, err
		}
		id = captured
	}
	if err := lockQuarantine(ctx); err != nil {
		return id, err
	}
	defer unlockQuarantine()
	dir, err := q.openQDir()
	if err != nil {
		return id, err
	}
	defer dir.Close()
	m, err := q.loadMetaForAction(dir, path, id, expected, true)
	if err != nil {
		return id, err
	}
	f, err := q.ops.openAt(dir, id+".payload", false)
	if err != nil {
		if m.State == "deleting" && os.IsNotExist(err) {
			m.State = "deleted"
			m.StageDir = ""
			m.ReviewReason = ""
			return id, writeMeta(q.ops, dir, m, false)
		}
		return id, fmt.Errorf("%w: %v", errQuarantineCorrupt, err)
	}
	got, err := openedDigest(ctx, f)
	f.Close()
	if err != nil || got != m.Sha256 {
		return id, fmt.Errorf("%w: quarantine bytes changed", errQuarantineCorrupt)
	}
	if m.State != "deleting" {
		m.State = "deleting"
		if err := writeMeta(q.ops, dir, m, false); err != nil {
			return id, err
		}
	}
	if err := q.ops.removeAt(dir, id+".payload"); err != nil && !os.IsNotExist(err) {
		return id, err
	}
	m.State = "deleted"
	m.StageDir = ""
	m.ReviewReason = ""
	return id, writeMeta(q.ops, dir, m, false)
}

func isOrphanTempName(name string) (id string, ok bool) {
	for _, marker := range []string{".meta.tmp-", ".capture-"} {
		if idx := strings.Index(name, marker); idx == 32 && len(name) > idx+len(marker) {
			prefix := name[:32]
			if objectID.MatchString(prefix) {
				return prefix, true
			}
		}
	}
	return "", false
}

type origInspection int

const (
	origMissing origInspection = iota
	origMatching
	origDifferent
	origUnverified
)

func (q *quarantine) inspectOriginal(ctx context.Context, origPath, expectedParentID, expectedDigest string) origInspection {
	parent, err := q.ops.openDirectory(filepath.Dir(origPath))
	if err != nil {
		if os.IsNotExist(err) {
			return origMissing
		}
		return origUnverified
	}
	defer parent.Close()
	if q.ops.parentIdentity(parent) != expectedParentID {
		return origMissing
	}
	f, err := q.ops.openAt(parent, filepath.Base(origPath), false)
	if err != nil {
		if os.IsNotExist(err) {
			return origMissing
		}
		return origUnverified
	}
	defer f.Close()
	got, err := openedDigest(ctx, f)
	if err != nil {
		if strings.Contains(err.Error(), "invalid regular file") {
			return origDifferent
		}
		return origUnverified
	}
	if got == expectedDigest {
		return origMatching
	}
	return origDifferent
}

func (q *quarantine) verifyStoredPayload(ctx context.Context, dir *os.File, id, expected string) (exists bool, match bool, err error) {
	f, err := q.ops.openAt(dir, id+".payload", false)
	if err != nil {
		if os.IsNotExist(err) {
			return false, false, nil
		}
		return true, false, err
	}
	defer f.Close()
	got, derr := openedDigest(ctx, f)
	if derr != nil {
		return true, false, derr
	}
	return true, got == expected, nil
}

func (q *quarantine) markReviewRequired(dir *os.File, m *quarantineMeta, reason string, report *ReconcileReport) {
	m.State = "review_required"
	m.ReviewReason = reason
	_ = writeMeta(q.ops, dir, m, false)
	report.ReviewRequired++
}

func (q *quarantine) reconcilePrepared(ctx context.Context, dir *os.File, m *quarantineMeta, payloadIDs map[string]bool, report *ReconcileReport) {
	id := m.ID
	exists, match, _ := q.verifyStoredPayload(ctx, dir, id, m.Sha256)
	if !exists {
		if m.StageDir != "" {
			if parent, err := q.ops.openDirectory(filepath.Dir(m.OrigPath)); err == nil {
				parentOK := q.ops.parentIdentity(parent) == m.ParentID
				if parentOK {
					outcome, _ := q.ops.reconcileStage(ctx, parent, filepath.Base(m.OrigPath), m.StageDir, "")
					_ = parent.Close()
					if outcome == stageRollbackConflict {
						q.markReviewRequired(dir, m, "staged_source_rollback_conflict", report)
						return
					}
					if outcome == stageRolledBackSource || outcome == stageCleanedEmpty {
						report.CleanedStageDirs++
					}
				} else {
					_ = parent.Close()
				}
			}
		}
		if err := q.ops.removeAt(dir, id+".meta.json"); err == nil {
			report.RolledBackPrepared++
		} else {
			report.ReviewRequired++
		}
		return
	}
	if !match {
		if q.inspectOriginal(ctx, m.OrigPath, m.ParentID, m.Sha256) == origMatching {
			_ = q.ops.removeAt(dir, id+".payload")
			delete(payloadIDs, id)
			_ = q.ops.removeAt(dir, id+".meta.json")
			report.RolledBackPrepared++
			return
		}
		q.markReviewRequired(dir, m, "prepared_payload_corrupt_original_absent", report)
		return
	}
	if m.StageDir != "" {
		if parent, err := q.ops.openDirectory(filepath.Dir(m.OrigPath)); err == nil {
			parentOK := q.ops.parentIdentity(parent) == m.ParentID
			var outcome stageOutcome
			if parentOK {
				outcome, _ = q.ops.reconcileStage(ctx, parent, filepath.Base(m.OrigPath), m.StageDir, m.Sha256)
			}
			_ = parent.Close()
			if parentOK {
				switch outcome {
				case stageCompletedUnlink:
					_ = q.ops.chmodPayload(filepath.Join(dir.Name(), id+".payload"))
					m.StageDir = ""
					m.State = "active"
					_ = writeMeta(q.ops, dir, m, false)
					report.CleanedStageDirs++
					report.PromotedActive++
					report.ActiveObjects++
					return
				case stageRolledBackSource:
					_ = q.ops.removeAt(dir, id+".payload")
					delete(payloadIDs, id)
					_ = q.ops.removeAt(dir, id+".meta.json")
					report.CleanedStageDirs++
					report.RolledBackPrepared++
					return
				case stageRollbackConflict:
					q.markReviewRequired(dir, m, "stage_digest_mismatch_rollback_conflict", report)
					return
				case stageCleanedEmpty:
					report.CleanedStageDirs++
				}
			}
		}
	}
	switch q.inspectOriginal(ctx, m.OrigPath, m.ParentID, m.Sha256) {
	case origMissing, origDifferent:
		_ = q.ops.chmodPayload(filepath.Join(dir.Name(), id+".payload"))
		m.StageDir = ""
		m.State = "active"
		if err := writeMeta(q.ops, dir, m, false); err != nil {
			report.ReviewRequired++
			return
		}
		report.PromotedActive++
		report.ActiveObjects++
	case origMatching:
		if m.TransferMode == "cross_volume" {
			if err := q.ops.removeAt(dir, id+".payload"); err == nil {
				delete(payloadIDs, id)
				if merr := q.ops.removeAt(dir, id+".meta.json"); merr == nil {
					report.RolledBackPrepared++
					return
				}
			}
		}
		q.markReviewRequired(dir, m, "prepared_payload_and_matching_original_both_exist", report)
	default:
		q.markReviewRequired(dir, m, "prepared_original_unverifiable", report)
	}
}

func (q *quarantine) reconcileMetaEntry(ctx context.Context, dir *os.File, id string, payloadIDs map[string]bool, report *ReconcileReport) {
	report.ScannedObjects++
	m, err := q.readMetaStrict(dir, id)
	if err != nil {
		report.CorruptMeta++
		report.ReviewRequired++
		return
	}
	switch m.State {
	case "restored", "deleted":
		if payloadIDs[id] {
			if err := q.ops.removeAt(dir, id+".payload"); err == nil {
				delete(payloadIDs, id)
				report.CleanedTerminalBody++
			} else {
				report.ReviewRequired++
			}
		}
	case "deleting":
		if payloadIDs[id] {
			if err := q.ops.removeAt(dir, id+".payload"); err == nil {
				delete(payloadIDs, id)
				report.CleanedTerminalBody++
			} else if !os.IsNotExist(err) {
				report.ReviewRequired++
				return
			}
		}
		m.State = "deleted"
		m.StageDir = ""
		m.ReviewReason = ""
		if err := writeMeta(q.ops, dir, m, false); err != nil {
			report.ReviewRequired++
			return
		}
		report.CompletedDeletes++
	case "active":
		exists, match, _ := q.verifyStoredPayload(ctx, dir, id, m.Sha256)
		if !exists || !match {
			q.markReviewRequired(dir, m, "active_payload_missing_or_corrupt", report)
			return
		}
		_ = q.ops.chmodPayload(filepath.Join(dir.Name(), id+".payload"))
		report.ActiveObjects++
	case "review_required":
		report.ReviewRequired++
	case "prepared":
		q.reconcilePrepared(ctx, dir, m, payloadIDs, report)
	default:
		report.CorruptMeta++
		report.ReviewRequired++
	}
}

// Reconcile inspects quarantine state left by crashes/power loss and recovers
// provably safe transitions without destroying unverified evidence or new files.
func (q *quarantine) Reconcile(ctx context.Context) (ReconcileReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var report ReconcileReport
	if _, err := os.Lstat(q.dir); os.IsNotExist(err) {
		return report, nil
	}
	if err := lockQuarantine(ctx); err != nil {
		return report, err
	}
	defer unlockQuarantine()
	dir, err := q.openQDir()
	if err != nil {
		return report, err
	}
	defer dir.Close()
	entries, err := os.ReadDir(dir.Name())
	if err != nil {
		return report, err
	}
	metaIDs := make([]string, 0, len(entries))
	metaSet := map[string]bool{}
	payloadSet := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() {
			if _, ok := isOrphanTempName(name); ok {
				if q.ops.removeAt(dir, name) == nil {
					report.CleanedOrphanTemp++
				} else {
					report.ReviewRequired++
				}
				continue
			}
			if strings.HasSuffix(name, ".meta.json") {
				id := strings.TrimSuffix(name, ".meta.json")
				if objectID.MatchString(id) {
					metaIDs = append(metaIDs, id)
					metaSet[id] = true
					continue
				}
			}
			if strings.HasSuffix(name, ".payload") {
				id := strings.TrimSuffix(name, ".payload")
				if objectID.MatchString(id) {
					payloadSet[id] = true
					continue
				}
			}
		}
		report.ReviewRequired++
	}
	sort.Strings(metaIDs)
	for _, id := range metaIDs {
		q.reconcileMetaEntry(ctx, dir, id, payloadSet, &report)
	}
	for id := range payloadSet {
		if !metaSet[id] {
			report.ReviewRequired++
		}
	}
	_ = q.ops.syncDir(dir)
	return report, nil
}

// Legacy path-only entry points cannot authorize destructive actions.
func (q *quarantine) QuarantineFile(path string) error {
	return fmt.Errorf("digest-bound action required")
}
func (q *quarantine) Restore(path string) error {
	return fmt.Errorf("quarantine object identity required")
}
func (q *quarantine) Delete(path string) error { return fmt.Errorf("digest-bound action required") }
