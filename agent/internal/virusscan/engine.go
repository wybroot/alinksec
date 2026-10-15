package virusscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const maxFileSize int64 = 500 << 20
const ioLimitRate int64 = 10 << 20
const cacheMaxEntries = 200_000
const scanCoverage = "SHA256 of regular files <=500MiB; internal rules inspect first 2MiB of eligible files <=50MiB; symlinks, special files, virtual/container filesystems and Agent work directory excluded; archives not expanded"

// File metadata never proves unchanged content; legacy caches cannot bypass reads.
type cacheEntry struct {
	Size   int64 `json:"s"`
	ModSec int64 `json:"m"`
}
type Engine struct {
	mu        sync.Mutex
	db        *SigDB
	cache     map[string]cacheEntry
	whitelist []whitelistEntry
	log       *slog.Logger
}

func NewEngine(workDir string, log *slog.Logger) *Engine {
	return &Engine{db: LoadDB(workDir), cache: map[string]cacheEntry{}, whitelist: loadWhitelist(workDir), log: log}
}
func (e *Engine) Scan(taskID string, mode pb.CmdVirusScan_Mode, paths []string, workDir string) *pb.RptVirusResult {
	return e.ScanCommand(context.Background(), &pb.CmdVirusScan{TaskId: taskID, Mode: mode, Paths: paths, ExecutionContract: 2}, workDir)
}
func (e *Engine) ScanCommand(ctx context.Context, cmd *pb.CmdVirusScan, workDir string) *pb.RptVirusResult {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.refresh(workDir)
	start := time.Now()
	r := &pb.RptVirusResult{TaskId: cmd.GetTaskId(), Mode: rptMode(cmd.GetMode()), ExecutionContract: 2, Coverage: scanCoverage, Status: pb.RptVirusResult_COMPLETE}
	finish := func() *pb.RptVirusResult { r.DurationMs = uint32(time.Since(start).Milliseconds()); return r }
	if e.db != nil {
		r.DbVersion = e.db.Version
	}
	fail := func(code string) *pb.RptVirusResult {
		r.Status = pb.RptVirusResult_FAILED
		issue(r, "", code)
		return finish()
	}
	if cmd.GetExecutionContract() != 2 {
		return fail("unsupported_contract")
	}
	if e.db != nil && !e.db.Valid {
		return fail("invalid_signatures")
	}
	if e.db == nil || len(e.db.hashes)+len(e.db.rules) == 0 {
		return fail("no_signatures")
	}
	if cmd.GetExpectedDbVersion() != "" && cmd.GetExpectedDbVersion() != r.DbVersion {
		return fail("signature_version_changed")
	}
	if cmd.GetMode() != pb.CmdVirusScan_QUICK && cmd.GetMode() != pb.CmdVirusScan_FULL && cmd.GetMode() != pb.CmdVirusScan_CUSTOM {
		return fail("invalid_mode")
	}
	seconds, files, bytesLimit := cmd.GetTimeLimitSec(), cmd.GetMaxFiles(), cmd.GetMaxTotalBytes()
	if seconds == 0 {
		seconds = 7200
	}
	if files == 0 {
		files = 100000
	}
	if bytesLimit == 0 {
		bytesLimit = 20 << 30
	}
	if seconds > 7200 || files > 100000 || bytesLimit > 20<<30 {
		return fail("invalid_budget")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
	defer cancel()
	roots := cmd.GetPaths()
	switch cmd.GetMode() {
	case pb.CmdVirusScan_QUICK:
		roots = quickScanRoots()
	case pb.CmdVirusScan_FULL:
		roots = fullScanRoots()
	}
	if len(roots) == 0 || len(roots) > 64 {
		return fail("invalid_roots")
	}
	seen := map[string]bool{}
	visited := uint32(0)
	var walk func(string, string, int) error
	walk = func(path, scope string, depth int) error {
		if ctx.Err() != nil || r.FilesSeen >= files || visited >= files*4 || r.BytesRead >= bytesLimit {
			return errScanBudget
		}
		visited++
		abs, err := filepath.Abs(path)
		if err != nil || !utf8.ValidString(abs) {
			scanFailure(r, path, "invalid_path")
			return nil
		}
		key := pathKey(abs)
		if seen[key] {
			return nil
		}
		seen[key] = true
		if protectedPath(abs, workDir) || isExcludedDir(abs) || e.whitelisted(abs, "") {
			r.FilesSkipped++
			return nil
		}
		st, err := os.Lstat(abs)
		if err != nil {
			scanFailure(r, abs, "unreadable")
			return nil
		}
		if st.Mode()&os.ModeSymlink != 0 || (!st.IsDir() && !st.Mode().IsRegular()) {
			r.FilesSkipped++
			return nil
		}
		if st.IsDir() {
			if depth >= 64 {
				scanFailure(r, abs, "depth_limit")
				return nil
			}
			canonical, err := filepath.EvalSymlinks(abs)
			if err != nil || !within(canonical, scope) {
				scanFailure(r, abs, "parent_changed")
				return nil
			}
			f, err := openDirectory(abs)
			if err != nil {
				scanFailure(r, abs, "unreadable_directory")
				return nil
			}
			defer f.Close()
			fst, err := f.Stat()
			if err != nil || !os.SameFile(st, fst) {
				scanFailure(r, abs, "directory_changed")
				return nil
			}
			for {
				entries, err := f.ReadDir(128)
				for _, d := range entries {
					if err := walk(filepath.Join(abs, d.Name()), scope, depth+1); err != nil {
						return err
					}
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					scanFailure(r, abs, "unreadable_directory")
					break
				}
			}
			return nil
		}
		r.FilesSeen++
		if len(abs) > 512 {
			scanFailure(r, abs, "report_path_limit")
			return nil
		}
		if st.Size() > maxFileSize {
			r.FilesSkipped++
			issue(r, abs, "oversize")
			return nil
		}
		canonical, err := filepath.EvalSymlinks(filepath.Dir(abs))
		if err != nil || !within(canonical, scope) {
			scanFailure(r, abs, "parent_changed")
			return nil
		}
		if protectedPath(filepath.Join(canonical, filepath.Base(abs)), workDir) {
			r.FilesSkipped++
			return nil
		}
		snap, err := readSnapshotScoped(ctx, abs, maxFileSize, bytesLimit-r.BytesRead, true, scope, workDir)
		r.BytesRead += snap.bytesRead
		if errors.Is(err, errScanBudget) {
			scanFailure(r, abs, "budget_exhausted")
			return errScanBudget
		}
		if err != nil {
			scanFailure(r, abs, "read_failed_or_changed")
			return nil
		}
		r.FilesScanned++
		if e.whitelisted(abs, snap.sum) {
			r.FilesSkipped++
			return nil
		}
		if finding := e.detect(abs, snap); finding != nil {
			id, err := NewQuarantine(workDir).QuarantineExpected(ctx, abs, snap.sum)
			if err != nil {
				finding.QuarantineId = id
				finding.ActionTaken = "alert_only"
				finding.ActionError = actionErrorCode(err)
			} else {
				finding.ActionTaken = "quarantined"
				finding.QuarantineId = id
			}
			r.Findings = append(r.Findings, finding)
			if len(r.Findings) >= 1000 {
				issue(r, "", "finding_limit")
				return errScanBudget
			}
		}
		return nil
	}
	for _, root := range roots {
		if !filepath.IsAbs(root) || strings.ContainsRune(root, 0) || len(root) > 4096 {
			scanFailure(r, root, "invalid_root")
			continue
		}
		abs := filepath.Clean(root)
		scope := abs
		if st, err := os.Lstat(abs); err == nil && !st.IsDir() {
			scope = filepath.Dir(abs)
		}
		scope, err := filepath.EvalSymlinks(scope)
		if err != nil {
			scanFailure(r, abs, "root_unavailable")
			continue
		}
		if err := walk(abs, scope, 0); err != nil {
			r.BudgetExhausted = true
			issue(r, "", "budget_exhausted")
			break
		}
	}
	if r.FilesFailed > 0 || r.BudgetExhausted {
		r.Status = pb.RptVirusResult_PARTIAL
		if r.FilesScanned == 0 {
			r.Status = pb.RptVirusResult_FAILED
		}
	}
	return finish()
}

var errScanBudget = errors.New("scan budget exhausted")

func issue(r *pb.RptVirusResult, path, code string) {
	if len(r.Issues) < 32 {
		path = strings.ToValidUTF8(path, "�")
		if len(path) > 4096 {
			path = path[:4096]
			for !utf8.ValidString(path) {
				path = path[:len(path)-1]
			}
		}
		r.Issues = append(r.Issues, &pb.VirusScanIssue{Path: path, Code: code})
	}
}
func scanFailure(r *pb.RptVirusResult, path, code string) { r.FilesFailed++; issue(r, path, code) }
func pathKey(path string) string {
	if runtime.GOOS == "windows" {
		return strings.ToLower(filepath.Clean(path))
	}
	return filepath.Clean(path)
}
func within(path, root string) bool {
	rel, err := filepath.Rel(pathKey(root), pathKey(path))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
func protectedPath(path, workDir string) bool {
	abs, err := filepath.Abs(workDir)
	if err == nil && within(path, abs) {
		return true
	}
	exe, err := os.Executable()
	return err == nil && pathKey(path) == pathKey(exe)
}
func (e *Engine) detect(path string, s snapshot) *pb.VirusFinding {
	entry, hit := e.db.Lookup(s.sum)
	engine, name, severity := "hash", entry.Name, entry.Severity
	if !hit {
		r := matchRules(e.db.rules, path, s.info.Size(), s.head)
		if r == nil {
			return nil
		}
		engine, name, severity = "rule", r.Name, r.Severity
	}
	return &pb.VirusFinding{Path: path, Name: name, Sha256: s.sum, Size: uint64(s.info.Size()), Engine: engine, Severity: pb.Severity(severity)}
}
func (e *Engine) CheckAndQuarantine(path, workDir string) *pb.VirusFinding {
	return e.CheckFile(path, workDir, true)
}
func (e *Engine) CheckFile(path, workDir string, quarantine bool) *pb.VirusFinding {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.refresh(workDir)
	if !utf8.ValidString(path) || len(path) > 512 || e.db == nil || !e.db.Valid || len(e.db.hashes)+len(e.db.rules) == 0 || protectedPath(path, workDir) || isExcludedDir(path) || e.whitelisted(path, "") {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s, err := readSnapshotScoped(ctx, path, maxFileSize, 20<<20, true, "", workDir)
	if err != nil {
		e.log.Debug("周期检测未覆盖文件", "path", path, "reason", actionErrorCode(err))
		return nil
	}
	if e.whitelisted(path, s.sum) {
		return nil
	}
	finding := e.detect(path, s)
	if finding == nil {
		return nil
	}
	finding.ActionTaken = "alert_only"
	if quarantine {
		id, err := NewQuarantine(workDir).QuarantineExpected(ctx, path, s.sum)
		if err != nil {
			finding.QuarantineId = id
			finding.ActionError = actionErrorCode(err)
		} else {
			finding.ActionTaken = "quarantined"
			finding.QuarantineId = id
		}
	}
	return finding
}

type snapshot struct {
	sum       string
	head      []byte
	info      os.FileInfo
	bytesRead uint64
}

func readSnapshot(ctx context.Context, path string, maxSize int64, budget uint64, limited bool) (snapshot, error) {
	return readSnapshotScoped(ctx, path, maxSize, budget, limited, "", "")
}
func readSnapshotScoped(ctx context.Context, path string, maxSize int64, budget uint64, limited bool, scope, workDir string) (snapshot, error) {
	var s snapshot
	f, parent, err := openRegular(path, false)
	if err != nil {
		return s, err
	}
	defer f.Close()
	defer parent.Close()
	if scope != "" && !within(parent.Name(), scope) || workDir != "" && protectedPath(filepath.Join(parent.Name(), filepath.Base(path)), workDir) {
		return s, fmt.Errorf("opened parent escaped scan scope")
	}
	s.info, err = f.Stat()
	if err != nil || !s.info.Mode().IsRegular() || s.info.Size() > maxSize {
		return s, fmt.Errorf("invalid regular file")
	}
	h := sha256.New()
	buf := make([]byte, 64<<10)
	started := time.Now()
	for {
		if ctx.Err() != nil {
			return s, errScanBudget
		}
		n, err := f.Read(buf)
		if n > 0 {
			s.bytesRead += uint64(n)
			if s.bytesRead > budget || s.bytesRead > uint64(maxSize) {
				return s, errScanBudget
			}
			h.Write(buf[:n])
			if len(s.head) < ruleHeadBytes {
				count := min(n, ruleHeadBytes-len(s.head))
				s.head = append(s.head, buf[:count]...)
			}
			if limited {
				delay := time.Duration(s.bytesRead)*time.Second/time.Duration(ioLimitRate) - time.Since(started)
				if delay > 0 {
					timer := time.NewTimer(delay)
					select {
					case <-ctx.Done():
						timer.Stop()
						return s, errScanBudget
					case <-timer.C:
					}
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return s, err
		}
	}
	after, err := f.Stat()
	current, cerr := statAt(parent, filepath.Base(path))
	if err != nil || cerr != nil || !os.SameFile(s.info, after) || !os.SameFile(after, current) || after.Size() != s.info.Size() || uint64(after.Size()) != s.bytesRead || !after.ModTime().Equal(s.info.ModTime()) || !current.Mode().IsRegular() {
		return s, fmt.Errorf("file changed during read")
	}
	s.sum = hex.EncodeToString(h.Sum(nil))
	return s, nil
}
func isExcludedDir(path string) bool {
	p := filepath.ToSlash(pathKey(path))
	if runtime.GOOS == "windows" {
		return strings.HasSuffix(p, "/windows/system32/drivers")
	}
	if p == "/dev/shm" || strings.HasPrefix(p, "/dev/shm/") {
		return false
	}
	for _, d := range []string{"/proc", "/sys", "/dev", "/run", "/var/lib/docker", "/.snapshots"} {
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}
func hashFileLimited(path string) (string, error) {
	s, err := readSnapshot(context.Background(), path, maxFileSize, uint64(maxFileSize), true)
	return s.sum, err
}
func fileSha256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, (20<<20)+1))
	if err != nil {
		return "", err
	}
	if n > 20<<20 {
		return "", fmt.Errorf("signature package exceeds 20MiB")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func cachePath(workDir string) string { return filepath.Join(workDir, "virus", "cache.json") }
func rptMode(m pb.CmdVirusScan_Mode) pb.RptVirusResult_Mode {
	switch m {
	case pb.CmdVirusScan_FULL:
		return pb.RptVirusResult_FULL
	case pb.CmdVirusScan_CUSTOM:
		return pb.RptVirusResult_CUSTOM
	default:
		return pb.RptVirusResult_QUICK
	}
}
