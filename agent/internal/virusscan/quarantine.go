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
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
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

var objectID = regexp.MustCompile(`^[0-9a-f]{32}$`)
var digestID = regexp.MustCompile(`^[0-9a-f]{64}$`)

type quarantine struct {
	dir     string
	workDir string
}
type quarantineMeta struct {
	ID       string `json:"id"`
	OrigPath string `json:"orig_path"`
	QuarFile string `json:"quar_file"`
	Sha256   string `json:"sha256"`
	Size     int64  `json:"size"`
	QuarAt   int64  `json:"quar_at"`
	Mode     uint32 `json:"mode"`
	UID      int    `json:"uid"`
	GID      int    `json:"gid"`
	ParentID string `json:"parent_id"`
	State    string `json:"state"`
	Security string `json:"security"`
}

func NewQuarantine(workDir string) *quarantine {
	return &quarantine{dir: QuarantineDir(workDir), workDir: workDir}
}
func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func actionErrorCode(err error) string {
	if errors.Is(err, errScanBudget) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "budget_exhausted"
	}
	if err == nil {
		return ""
	}
	return "file_identity_or_io_failure"
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
func writeMeta(dir *os.File, m *quarantineMeta, create bool) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	name := m.ID + ".meta.json"
	if !create {
		name = m.ID + ".meta.tmp-" + randomID()
	}
	f, err := openAt(dir, name, true)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	f.Close()
	if err != nil {
		removeAt(dir, name)
		return err
	}
	if !create {
		// Private directory: metadata replacement cannot be influenced by ordinary
		// users. Payload identities are verified again before every action.
		err = os.Rename(filepath.Join(dir.Name(), name), filepath.Join(dir.Name(), m.ID+".meta.json"))
	}
	return err
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
	f, parent, err := openRegular(path, true)
	if err != nil {
		return "", err
	}
	defer f.Close()
	defer parent.Close()
	if protectedPath(filepath.Join(parent.Name(), filepath.Base(path)), q.workDir) {
		return "", fmt.Errorf("resolved target is protected Agent state")
	}
	got, err := openedDigest(ctx, f)
	if err != nil || got != expected {
		return "", fmt.Errorf("target bytes differ from detection")
	}
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	dir, err := q.directory()
	if err != nil {
		return "", err
	}
	defer dir.Close()
	uid, gid := originalOwner(info)
	security, err := originalSecurity(f)
	if err != nil {
		return "", err
	}
	id := randomID()
	m := &quarantineMeta{ID: id, OrigPath: filepath.Clean(path), QuarFile: filepath.Join(q.dir, id+".payload"), Sha256: expected, Size: info.Size(), QuarAt: time.Now().Unix(), Mode: uint32(info.Mode().Perm()), UID: uid, GID: gid, ParentID: parentIdentity(parent), State: "prepared"}
	m.Security = security
	if m.ParentID == "" {
		return "", fmt.Errorf("parent identity unavailable")
	}
	if err := writeMeta(dir, m, true); err != nil {
		return "", err
	}
	name := id + ".payload"
	err = renamePinned(parent, f, filepath.Base(path), dir, name)
	if err == nil {
		got, err = openedDigest(ctx, f)
		if err == nil && got != expected {
			err = fmt.Errorf("moved bytes differ from detection")
		}
	}
	// Copy into a new Agent-owned inode: writers holding the original descriptor
	// cannot alter the stored sample after capture. Publish only matching bytes.
	if err == nil {
		temp := id + ".capture-" + randomID()
		out, e := openAt(dir, temp, true)
		if e == nil {
			_, e = f.Seek(0, io.SeekStart)
			if e == nil {
				e = copyBounded(ctx, out, f, maxFileSize)
			}
			if e == nil {
				var copied string
				copied, e = openedDigest(ctx, out)
				if e == nil && copied != expected {
					e = fmt.Errorf("captured bytes changed")
				}
			}
			if e == nil {
				e = out.Sync()
			}
			out.Close()
		}
		if e == nil {
			// Windows cannot replace the captured destination while this source
			// descriptor remains open. The verified new inode is ready to publish.
			e = f.Close()
		}
		if e == nil {
			e = os.Rename(filepath.Join(dir.Name(), temp), filepath.Join(dir.Name(), name))
		}
		if e != nil {
			removeAt(dir, temp)
			err = e
		}
	}
	if err != nil {
		// On cross-volume moves the original is retained. On a changed source, move
		// the captured candidate back only if the original name remains vacant.
		if moved, e := openMutatingAt(dir, name); e == nil {
			rollback := renamePinned(dir, moved, name, parent, filepath.Base(path))
			moved.Close()
			if rollback != nil {
				return id, fmt.Errorf("quarantine incomplete; retained object %s", id)
			}
		}
		removeAt(dir, id+".meta.json")
		return "", err
	}
	// No executable payload; Windows protection is the private Agent directory ACL.
	if runtime.GOOS != "windows" {
		if err := os.Chmod(filepath.Join(dir.Name(), name), 0400); err != nil {
			return id, err
		}
	}
	m.State = "active"
	if err := writeMeta(dir, m, false); err != nil {
		return id, fmt.Errorf("payload retained with prepared metadata: %s", id)
	}
	return id, nil
}
func (q *quarantine) loadMeta(dir *os.File, path, id, expected string) (*quarantineMeta, error) {
	if !objectID.MatchString(id) || !digestID.MatchString(strings.ToLower(expected)) || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("missing object identity")
	}
	f, err := openAt(dir, id+".meta.json", false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(data) > 65536 {
		return nil, fmt.Errorf("invalid metadata")
	}
	var m quarantineMeta
	if json.Unmarshal(data, &m) != nil || m.ID != id || pathKey(m.OrigPath) != pathKey(path) || m.Sha256 != strings.ToLower(expected) || m.QuarFile != filepath.Join(q.dir, id+".payload") || m.ParentID == "" || m.Size < 0 || m.Size > maxFileSize || (m.State != "active" && m.State != "prepared") {
		return nil, fmt.Errorf("quarantine identity mismatch")
	}
	return &m, nil
}
func (q *quarantine) RestoreExpected(ctx context.Context, path, id, expected string) error {
	if err := lockQuarantine(ctx); err != nil {
		return err
	}
	defer unlockQuarantine()
	dir, err := q.directory()
	if err != nil {
		return err
	}
	defer dir.Close()
	m, err := q.loadMeta(dir, path, id, expected)
	if err != nil {
		return err
	}
	f, err := openAt(dir, id+".payload", false)
	if err != nil {
		return err
	}
	defer f.Close()
	got, err := openedDigest(ctx, f)
	if err != nil || got != m.Sha256 {
		return fmt.Errorf("quarantine bytes changed")
	}
	parent, err := openDirectory(filepath.Dir(m.OrigPath))
	if err != nil {
		return err
	}
	defer parent.Close()
	if parentIdentity(parent) != m.ParentID {
		return fmt.Errorf("original parent changed; recovery requires manual review")
	}
	if err := restoreCopy(ctx, f, parent, filepath.Base(m.OrigPath), os.FileMode(m.Mode), m.UID, m.GID, m.Security); err != nil {
		return err
	}
	// Successful copy leaves evidence until metadata records the real outcome.
	m.State = "restored"
	if err := writeMeta(dir, m, false); err != nil {
		return err
	}
	if err := removeAt(dir, id+".payload"); err != nil {
		return err
	}
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
	dir, err := q.directory()
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
	f, err := openAt(dir, id+".payload", false)
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
	dir, err := q.directory()
	if err != nil {
		return id, err
	}
	defer dir.Close()
	m, err := q.loadMeta(dir, path, id, expected)
	if err != nil {
		return id, err
	}
	f, err := openAt(dir, id+".payload", false)
	if err != nil {
		return id, err
	}
	got, err := openedDigest(ctx, f)
	f.Close()
	if err != nil || got != m.Sha256 {
		return id, fmt.Errorf("quarantine bytes changed")
	}
	if err := removeAt(dir, id+".payload"); err != nil {
		return id, err
	}
	m.State = "deleted"
	return id, writeMeta(dir, m, false)
}

// Legacy path-only entry points cannot authorize destructive actions.
func (q *quarantine) QuarantineFile(path string) error {
	return fmt.Errorf("digest-bound action required")
}
func (q *quarantine) Restore(path string) error {
	return fmt.Errorf("quarantine object identity required")
}
func (q *quarantine) Delete(path string) error { return fmt.Errorf("digest-bound action required") }
