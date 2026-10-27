package virusscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/alinksec/alinksec-agent/internal/clamav"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/yara"
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
const scanCoverage = "SHA256 of regular files <=500MiB; internal rules inspect first 2MiB of eligible files <=50MiB; symlinks, special files, virtual/container filesystems and Agent work directory excluded; archives not expanded"

type Engine struct {
	mu             sync.Mutex
	db             *SigDB
	whitelist      []whitelistEntry
	log            *slog.Logger
	policyReader   func() ([]byte, error)
	ioBudget       func(context.Context, int) error
	clamav         *clamav.Client
	yara           *yara.Client
	realtimeIssues map[realtimeIssueKey]realtimeIssueWindow
}

func (e *Engine) SetClamAV(client *clamav.Client) { e.clamav = client }
func (e *Engine) SetYARA(client *yara.Client)     { e.yara = client }

// SetIOBudget must be called before publishing an engine. Active scans use
// their own immutable callback; the shared governor coordinates other engines.
func (e *Engine) SetIOBudget(wait func(context.Context, int) error) { e.ioBudget = wait }

type ioBudgetKey struct{}

func NewEngine(workDir string, log *slog.Logger) *Engine {
	return NewEngineWithPolicyReader(workDir, log, nil)
}

// NewEngineWithPolicyReader uses the pinned snapshot from construction onward.
// It must not open the editable policy, even while initializing the whitelist.
func NewEngineWithPolicyReader(workDir string, log *slog.Logger, reader func() ([]byte, error)) *Engine {
	e := &Engine{db: LoadDB(workDir), log: log, policyReader: reader}
	if reader != nil {
		data, err := reader()
		e.whitelist = parseWhitelist(data, err)
	} else {
		e.whitelist = loadWhitelist(workDir)
	}
	return e
}
func (e *Engine) Scan(taskID string, mode pb.CmdVirusScan_Mode, paths []string, workDir string) *pb.RptVirusResult {
	return e.ScanCommand(context.Background(), &pb.CmdVirusScan{TaskId: taskID, Mode: mode, Paths: paths, ExecutionContract: 2}, workDir)
}
func (e *Engine) ScanCommand(ctx context.Context, cmd *pb.CmdVirusScan, workDir string) *pb.RptVirusResult {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.refresh(workDir)
	start := time.Now()
	selected := cmd.GetEngine()
	if selected == "" {
		selected = "builtin"
	}
	useClamAV := selected == "clamav"
	useYARA := selected == "yara"
	external := useClamAV || useYARA
	r := &pb.RptVirusResult{TaskId: cmd.GetTaskId(), Mode: rptMode(cmd.GetMode()), ExecutionContract: 2, ScanEngine: selected, Coverage: scanCoverage, Status: pb.RptVirusResult_COMPLETE}
	fileLimit := maxFileSize
	if useClamAV {
		r.ExecutionContract = 3
		r.Coverage = "ClamAV INSTREAM of stable regular files <=20MiB; daemon archive/recursion/time limits apply; symlinks, special files, virtual/container filesystems and Agent work directory excluded; pinned reported engine version is not a complete signature corpus digest"
		fileLimit = clamav.MaxFileBytes
	}
	if useYARA {
		r.ExecutionContract = 4
		r.Coverage = "Native YARA isolated memory scan of stable regular files <=20MiB; exact UTF8 rule source SHA256 pinned; no includes, external data, archive expansion or process-memory scan; at most32 matching rule identifiers; symlinks, special files, virtual/container filesystems and Agent work directory excluded"
		fileLimit = yara.MaxFileBytes
	}
	finish := func() *pb.RptVirusResult { r.DurationMs = uint32(time.Since(start).Milliseconds()); return r }
	if e.db != nil && !external {
		r.DbVersion = e.db.Version
	}
	fail := func(code string) *pb.RptVirusResult {
		r.Status = pb.RptVirusResult_FAILED
		issue(r, "", code)
		return finish()
	}
	if selected != "builtin" && !external || cmd.GetExecutionContract() != r.ExecutionContract {
		return fail("unsupported_contract")
	}
	if !external && e.db != nil && !e.db.Valid {
		return fail("invalid_signatures")
	}
	if !external && (e.db == nil || len(e.db.hashes)+len(e.db.rules) == 0) {
		return fail("no_signatures")
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
	if e.ioBudget != nil {
		ctx = context.WithValue(ctx, ioBudgetKey{}, e.ioBudget)
	}
	if useClamAV {
		if e.clamav == nil {
			return fail("clamav_disabled")
		}
		version, err := e.clamav.Probe(ctx)
		if err != nil {
			return fail(clamav.Code(err))
		}
		r.DbVersion = version
		if cmd.GetExpectedDbVersion() == "" || cmd.GetExpectedDbVersion() != version {
			return fail("clamav_version_changed")
		}
	} else if useYARA {
		if e.yara == nil {
			return fail("yara_disabled")
		}
		version, err := e.yara.Probe(ctx)
		if err != nil {
			return fail(yara.Code(err))
		}
		r.DbVersion = version
		if cmd.GetExpectedDbVersion() == "" || cmd.GetExpectedDbVersion() != version {
			return fail("yara_version_changed")
		}
	} else if cmd.GetExpectedDbVersion() != "" && cmd.GetExpectedDbVersion() != r.DbVersion {
		return fail("signature_version_changed")
	}
	if cmd.GetMode() != pb.CmdVirusScan_QUICK && cmd.GetMode() != pb.CmdVirusScan_FULL && cmd.GetMode() != pb.CmdVirusScan_CUSTOM {
		return fail("invalid_mode")
	}
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
	seen := map[[32]byte]bool{}
	visited := uint32(0)
	var walk func(string, string, int) error
	walk = func(path, scope string, depth int) error {
		if ctx.Err() != nil || r.FilesSeen >= files || visited >= files*4 || r.BytesRead >= bytesLimit {
			return errScanBudget
		}
		visited++
		if e.ioBudget != nil && e.ioBudget(ctx, 4096) != nil {
			return errScanBudget
		}
		abs, err := filepath.Abs(path)
		if err != nil || !utf8.ValidString(abs) {
			scanFailure(r, path, "invalid_path")
			return nil
		}
		key := sha256.Sum256([]byte(pathKey(abs)))
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
		if st.Size() > fileLimit {
			if external {
				code := "clamav_file_limit"
				if useYARA {
					code = "yara_file_limit"
				}
				scanFailure(r, abs, code)
				return nil
			}
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
		var snap snapshot
		name := ""
		var matches []yara.Match
		if useClamAV {
			name, err = e.clamav.Scan(ctx, r.DbVersion, func(scanCtx context.Context, sink io.Writer) error {
				var readErr error
				snap, readErr = readSnapshotScopedSink(scanCtx, abs, fileLimit, bytesLimit-r.BytesRead, true, scope, workDir, sink)
				if errors.Is(readErr, errScanBudget) && scanCtx.Err() != nil && ctx.Err() == nil {
					return scanCtx.Err()
				}
				return readErr
			})
		} else if useYARA {
			matches, err = e.yara.Scan(ctx, r.DbVersion, func(scanCtx context.Context, sink io.Writer) error {
				var readErr error
				snap, readErr = readSnapshotScopedSink(scanCtx, abs, fileLimit, bytesLimit-r.BytesRead, true, scope, workDir, sink)
				if errors.Is(readErr, errScanBudget) && scanCtx.Err() != nil && ctx.Err() == nil {
					return scanCtx.Err()
				}
				return readErr
			})
		} else {
			snap, err = readSnapshotScoped(ctx, abs, fileLimit, bytesLimit-r.BytesRead, true, scope, workDir)
		}
		r.BytesRead += snap.bytesRead
		if errors.Is(err, errScanBudget) {
			scanFailure(r, abs, "budget_exhausted")
			return errScanBudget
		}
		if err != nil {
			code := "read_failed_or_changed"
			if useClamAV {
				code = clamav.Code(err)
			} else if useYARA {
				code = yara.Code(err)
			}
			scanFailure(r, abs, code)
			return nil
		}
		r.FilesScanned++
		if e.whitelisted(abs, snap.sum) {
			r.FilesSkipped++
			return nil
		}
		var finding *pb.VirusFinding
		if useClamAV {
			finding = clamavFinding(abs, snap, name, r.DbVersion)
		} else if useYARA {
			finding = yaraFinding(abs, snap, matches, r.DbVersion)
		} else {
			finding = e.detect(abs, snap)
		}
		if finding != nil {
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
	if e.db == nil || !e.db.Valid {
		return nil
	}
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
	useClamAV, useYARA := e.clamav.Realtime(), e.yara.Realtime()
	if !utf8.ValidString(path) || len(path) > 512 || (!useClamAV && !useYARA && (e.db == nil || !e.db.Valid || len(e.db.hashes)+len(e.db.rules) == 0)) || protectedPath(path, workDir) || isExcludedDir(path) || e.whitelisted(path, "") {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if e.ioBudget != nil {
		ctx = context.WithValue(ctx, ioBudgetKey{}, e.ioBudget)
	}
	var s snapshot
	var observed snapshot
	var nativeFinding *pb.VirusFinding
	var spent uint64
	consume := func(scanCtx context.Context, sink io.Writer) error {
		snap, err := readSnapshotScopedSink(scanCtx, path, 20<<20, (20<<20)-min(uint64(20<<20), spent), true, "", workDir, sink)
		observed = snap
		spent += snap.bytesRead
		if snap.sum != "" {
			s = snap
		}
		return err
	}
	var inputErr error
	consumeObserved := func(scanCtx context.Context, sink io.Writer) error {
		inputErr = consume(scanCtx, sink)
		if inputErr != nil && scanCtx.Err() != nil {
			inputErr = scanCtx.Err()
		}
		return inputErr
	}
	started := time.Now()
	if useClamAV {
		if version, err := e.clamav.Probe(ctx); err == nil {
			if name, err := e.clamav.Scan(ctx, version, consumeObserved); err == nil {
				nativeFinding = clamavFinding(path, s, name, version)
			} else {
				e.realtimeFailure("clamav", "scan", path, observed, spent, started, ctx, err, inputErr)
			}
		} else {
			e.realtimeFailure("clamav", "probe", path, observed, spent, started, ctx, err, nil)
		}
	}
	if useYARA && nativeFinding == nil && ctx.Err() == nil {
		inputErr = nil
		if version, err := e.yara.ProbeRealtime(ctx); err == nil {
			if matches, err := e.yara.Scan(ctx, version, consumeObserved); err == nil {
				nativeFinding = yaraFinding(path, s, matches, version)
			} else {
				e.realtimeFailure("yara", "scan", path, observed, spent, started, ctx, err, inputErr)
			}
		} else {
			e.realtimeFailure("yara", "probe", path, observed, spent, started, ctx, err, nil)
		}
	}
	// Native failures never suppress independent builtin detection from a fully
	// identity-checked snapshot. All reads share the 2sec/20MiB realtime budget.
	if s.sum == "" {
		var err error
		s, err = readSnapshotScoped(ctx, path, maxFileSize, (20<<20)-min(uint64(20<<20), spent), true, "", workDir)
		if err != nil {
			e.log.Debug("周期检测未覆盖文件", "path", path, "reason", actionErrorCode(err))
			return nil
		}
	}
	if e.whitelisted(path, s.sum) {
		return nil
	}
	finding := e.detect(path, s)
	if finding == nil {
		finding = nativeFinding
	}
	if finding == nil {
		return nil
	}
	finding.ActionTaken = "alert_only"
	if quarantine {
		id, err := NewQuarantine(workDir).QuarantineExpected(ctx, path, finding.Sha256)
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
	return readSnapshotScopedSink(ctx, path, maxSize, budget, limited, scope, workDir, nil)
}
func clamavFinding(path string, s snapshot, name, version string) *pb.VirusFinding {
	if name == "" || s.sum == "" || s.info == nil {
		return nil
	}
	return &pb.VirusFinding{Path: path, Name: name, Sha256: s.sum, Size: uint64(s.info.Size()), Engine: "clamav", EngineVersion: version, Severity: pb.Severity_SEV_HIGH}
}
func yaraFinding(path string, s snapshot, matches []yara.Match, version string) *pb.VirusFinding {
	if len(matches) == 0 || s.sum == "" || s.info == nil {
		return nil
	}
	ids := make([]string, 0, len(matches))
	for _, match := range matches {
		ids = append(ids, match.Rule)
	}
	return &pb.VirusFinding{Path: path, Name: matches[0].Rule, Sha256: s.sum, Size: uint64(s.info.Size()), Engine: "yara", EngineVersion: version, Severity: pb.Severity(matches[0].Severity), MatchedRules: ids}
}
func readSnapshotScopedSink(ctx context.Context, path string, maxSize int64, budget uint64, limited bool, scope, workDir string, sink io.Writer) (snapshot, error) {
	var s snapshot
	f, parent, err := openRegular(path, false)
	if err != nil {
		return s, err
	}
	defer f.Close()
	defer parent.Close()
	if scope != "" && !within(parent.Name(), scope) || workDir != "" && protectedPath(filepath.Join(parent.Name(), filepath.Base(path)), workDir) {
		return s, errSnapshotScope
	}
	s.info, err = f.Stat()
	if err != nil {
		return s, err
	}
	if !s.info.Mode().IsRegular() {
		return s, errSnapshotType
	}
	if s.info.Size() > maxSize {
		return s, errSnapshotSize
	}
	h := sha256.New()
	buf := acquireReadBuffer()
	defer releaseReadBuffer(buf)
	s.head = make([]byte, 0, min(s.info.Size(), ruleHeadBytes))
	started := time.Now()
	for {
		if ctx.Err() != nil {
			return s, errScanBudget
		}
		// Pace the remaining pinned bytes, with a one-byte EOF probe. Charging
		// a full buffer for a short tail or EOF needlessly consumes the deadline.
		want := int(min(int64(len(buf)), max(int64(1), s.info.Size()-int64(s.bytesRead))))
		wait, _ := ctx.Value(ioBudgetKey{}).(func(context.Context, int) error)
		if wait != nil && wait(ctx, want) != nil {
			return s, errScanBudget
		}
		n, err := f.Read(buf[:want])
		if n > 0 {
			s.bytesRead += uint64(n)
			if s.bytesRead > uint64(s.info.Size()) {
				return s, errSnapshotChanged
			}
			if s.bytesRead > budget || s.bytesRead > uint64(maxSize) {
				return s, errScanBudget
			}
			h.Write(buf[:n])
			if sink != nil {
				if _, err := sink.Write(buf[:n]); err != nil {
					return s, snapshotSinkError{err}
				}
			}
			if len(s.head) < ruleHeadBytes {
				count := min(n, ruleHeadBytes-len(s.head))
				s.head = append(s.head, buf[:count]...)
			}
			if limited && wait == nil {
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
		return s, errSnapshotChanged
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
