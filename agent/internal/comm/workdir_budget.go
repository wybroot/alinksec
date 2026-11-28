package comm

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/disk"
)

const (
	// defaultWorkDirHardLimit keeps the entire Agent work directory below 500 MiB (BKL-029).
	defaultWorkDirHardLimit         int64  = 480 << 20
	defaultMinFreeDiskBytes         uint64 = 128 << 20
	defaultCriticalFreeDiskBytes    uint64 = 32 << 20
	defaultEvidenceDirLimit         int64  = 32 << 20
	defaultEvidenceMaxFiles                = 200
	defaultStaleTempAge                    = time.Hour
	defaultTerminalQuarantineMetaAge       = 30 * 24 * time.Hour
	defaultBudgetScanInterval              = 30 * time.Second
)

var (
	errWorkdirBudgetExceeded = errors.New("agent workdir total disk budget exceeded")
	errInsufficientDiskSpace = errors.New("insufficient free disk space for agent workdir")
	queryFreeDiskSpace       = defaultQueryFreeDiskSpace
)

func defaultQueryFreeDiskSpace(path string) (uint64, error) {
	u, err := disk.Usage(path)
	if err != nil || u == nil {
		if err == nil {
			err = errors.New("disk usage unavailable")
		}
		return 0, err
	}
	return u.Free, nil
}

// WorkdirUsage captures purely numeric per-subsystem byte usage under Agent workDir.
// No host file paths or secret contents are included so diagnostics stay allowlisted.
type WorkdirUsage struct {
	TotalBytes      int64  `json:"totalBytes"`
	QueueBytes      int64  `json:"queueBytes"`
	QuarantineBytes int64  `json:"quarantineBytes"`
	EvidenceBytes   int64  `json:"evidenceBytes"`
	SignatureBytes  int64  `json:"signatureBytes"`
	UpgradeBytes    int64  `json:"upgradeBytes"`
	StateBytes      int64  `json:"stateBytes"`
	OtherBytes      int64  `json:"otherBytes"`
	HardLimitBytes  int64  `json:"hardLimitBytes"`
	FreeDiskBytes   uint64 `json:"freeDiskBytes"`
	ReclaimedBytes  int64  `json:"reclaimedBytes"`
	ReclaimedFiles  int64  `json:"reclaimedFiles"`
	BudgetRejects   uint64 `json:"budgetRejects"`
}

type workdirBudget struct {
	mu               sync.Mutex
	workDir          string
	hardLimit        int64
	minFreeDisk      uint64
	criticalFreeDisk uint64
	evidenceLimit    int64
	evidenceMaxFiles int
	staleTempAge     time.Duration
	terminalMetaAge  time.Duration
	scanInterval     time.Duration
	now              func() time.Time

	cached         WorkdirUsage
	freeKnown      bool
	lastScan       time.Time
	pendingDelta   int64
	reclaimedBytes int64
	reclaimedFiles int64
	budgetRejects  uint64
}

func newWorkdirBudget(workDir string) *workdirBudget {
	return &workdirBudget{
		workDir:          workDir,
		hardLimit:        defaultWorkDirHardLimit,
		minFreeDisk:      defaultMinFreeDiskBytes,
		criticalFreeDisk: defaultCriticalFreeDiskBytes,
		evidenceLimit:    defaultEvidenceDirLimit,
		evidenceMaxFiles: defaultEvidenceMaxFiles,
		staleTempAge:     defaultStaleTempAge,
		terminalMetaAge:  defaultTerminalQuarantineMetaAge,
		scanInterval:     defaultBudgetScanInterval,
		now:              time.Now,
	}
}

func (b *workdirBudget) Snapshot() WorkdirUsage {
	if b == nil {
		return WorkdirUsage{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.lastScan.IsZero() || b.now().Sub(b.lastScan) >= b.scanInterval {
		b.scanLocked()
	}
	usage := b.cached
	usage.HardLimitBytes = b.hardLimit
	usage.ReclaimedBytes = b.reclaimedBytes
	usage.ReclaimedFiles = b.reclaimedFiles
	usage.BudgetRejects = b.budgetRejects
	return usage
}

func (b *workdirBudget) Scan() WorkdirUsage {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.scanLocked()
	return b.cached
}

func (b *workdirBudget) noteDelta(delta int64) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pendingDelta += delta
	if delta < 0 || b.pendingDelta < 0 {
		// Invalidate cached scan after compaction/reclaim so freed headroom is seen immediately.
		b.lastScan = time.Time{}
		b.pendingDelta = 0
	}
}

func (b *workdirBudget) invalidate() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.lastScan = time.Time{}
	b.pendingDelta = 0
	b.mu.Unlock()
}

func (b *workdirBudget) scanLocked() {
	usage := WorkdirUsage{
		HardLimitBytes: b.hardLimit,
		ReclaimedBytes: b.reclaimedBytes,
		ReclaimedFiles: b.reclaimedFiles,
		BudgetRejects:  b.budgetRejects,
	}
	if b.workDir == "" {
		b.cached = usage
		b.lastScan = b.now()
		b.pendingDelta = 0
		return
	}
	if free, err := queryFreeDiskSpace(b.workDir); err == nil {
		usage.FreeDiskBytes = free
		b.freeKnown = true
	} else {
		usage.FreeDiskBytes = 0
		b.freeKnown = false
	}

	_ = filepath.WalkDir(b.workDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		sz := info.Size()
		if sz < 0 {
			return nil
		}
		usage.TotalBytes += sz
		rel, rerr := filepath.Rel(b.workDir, path)
		if rerr != nil {
			usage.OtherBytes += sz
			return nil
		}
		addCategoryBytes(&usage, filepath.ToSlash(rel), sz)
		return nil
	})
	b.cached = usage
	b.lastScan = b.now()
	b.pendingDelta = 0
}

func addCategoryBytes(usage *WorkdirUsage, slashRel string, sz int64) {
	switch {
	case slashRel == "queue" || strings.HasPrefix(slashRel, "queue/"):
		usage.QueueBytes += sz
	case slashRel == "virus/quarantine" || strings.HasPrefix(slashRel, "virus/quarantine/"):
		usage.QuarantineBytes += sz
	case slashRel == "evidence" || strings.HasPrefix(slashRel, "evidence/"):
		usage.EvidenceBytes += sz
	case slashRel == "virus" || strings.HasPrefix(slashRel, "virus/"):
		usage.SignatureBytes += sz
	case slashRel == "upgrade" || strings.HasPrefix(slashRel, "upgrade/"):
		usage.UpgradeBytes += sz
	case isProtectedStatePath(slashRel):
		usage.StateBytes += sz
	default:
		usage.OtherBytes += sz
	}
}

func isProtectedStatePath(slashRel string) bool {
	top := slashRel
	if idx := strings.IndexByte(slashRel, '/'); idx >= 0 {
		top = slashRel[:idx]
	}
	switch top {
	case "certs", "isolation", "evidence-state", "scap-state", "windowsupdate",
		"config-integrity", "file-protection", "ransom-etw",
		"state.yml", "state.yml.tmp", "policy.json", "policy.json.tmp",
		"isolated.json", "cmd-dedup.json", "asset-sequence.json",
		"asset-sequence.initialized.json", "config-integrity.enabled",
		"login-protection.json", "agent.yml":
		return true
	default:
		return strings.HasPrefix(top, "decoy")
	}
}

// Reclaim performs strictly non-destructive cleanup inside workDir.
// Unacknowledged offline queue entries, active/prepared quarantine samples,
// active signature databases, and Agent identity/recovery state are NEVER removed.
func (b *workdirBudget) Reclaim() (int64, int64) {
	if b == nil || b.workDir == "" {
		return 0, 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.reclaimLocked()
}

func (b *workdirBudget) reclaimLocked() (int64, int64) {
	now := b.now()
	var bytesFreed, filesFreed int64

	qDir := filepath.Join(b.workDir, "virus", "quarantine")
	if entries, err := os.ReadDir(qDir); err == nil {
		// Phase 1: remove stale temporary staging files left behind by interrupted quarantine writes.
		for _, entry := range entries {
			if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				continue
			}
			name := entry.Name()
			if !strings.Contains(name, ".meta.tmp-") && !strings.Contains(name, ".capture-") {
				continue
			}
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() || now.Sub(info.ModTime()) < b.staleTempAge {
				continue
			}
			if os.Remove(filepath.Join(qDir, name)) == nil {
				bytesFreed += info.Size()
				filesFreed++
			}
		}

		// Phase 2: remove aged terminal (deleted/restored) quarantine metadata when payload is absent.
		for _, entry := range entries {
			if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				continue
			}
			name := entry.Name()
			if !strings.HasSuffix(name, ".meta.json") {
				continue
			}
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 || now.Sub(info.ModTime()) < b.terminalMetaAge {
				continue
			}
			metaPath := filepath.Join(qDir, name)
			data, err := readRegularBounded(metaPath, 64<<10)
			if err != nil {
				continue
			}
			var meta struct {
				ID    string `json:"id"`
				State string `json:"state"`
			}
			if json.Unmarshal(data, &meta) != nil {
				continue
			}
			if meta.State != "deleted" && meta.State != "restored" {
				continue
			}
			id := strings.TrimSuffix(name, ".meta.json")
			if meta.ID != "" && meta.ID != id {
				continue
			}
			// Never drop metadata while a payload still exists on disk.
			if _, statErr := os.Lstat(filepath.Join(qDir, id+".payload")); !os.IsNotExist(statErr) {
				continue
			}
			if os.Remove(metaPath) == nil {
				bytesFreed += info.Size()
				filesFreed++
			}
		}
	}

	// Phase 3: enforce count and byte bounds on guard forensics dumps, pruning oldest first.
	evDir := filepath.Join(b.workDir, "evidence")
	if entries, err := os.ReadDir(evDir); err == nil {
		type evFile struct {
			path string
			size int64
			mod  time.Time
		}
		var files []evFile
		var evBytes int64
		for _, entry := range entries {
			if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			files = append(files, evFile{
				path: filepath.Join(evDir, entry.Name()),
				size: info.Size(),
				mod:  info.ModTime(),
			})
			evBytes += info.Size()
		}
		sort.Slice(files, func(i, j int) bool {
			return files[i].mod.Before(files[j].mod)
		})
		remaining := len(files)
		for _, f := range files {
			if (b.evidenceMaxFiles <= 0 || remaining <= b.evidenceMaxFiles) &&
				(b.evidenceLimit <= 0 || evBytes <= b.evidenceLimit) {
				break
			}
			if os.Remove(f.path) == nil {
				evBytes -= f.size
				remaining--
				bytesFreed += f.size
				filesFreed++
			}
		}
	}

	if filesFreed > 0 {
		b.reclaimedBytes += bytesFreed
		b.reclaimedFiles += filesFreed
		b.lastScan = time.Time{}
		b.pendingDelta = 0
	}
	return bytesFreed, filesFreed
}

func readRegularBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("invalid metadata file")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("oversized metadata file")
	}
	return data, nil
}

// CanAdmit validates both the total workdir hard cap (<500 MiB) and minimum
// free host disk headroom before admitting an offline queue record.
func (b *workdirBudget) CanAdmit(priority reportPriority, addBytes int64) error {
	if b == nil || addBytes <= 0 {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	if b.lastScan.IsZero() || now.Sub(b.lastScan) >= b.scanInterval || b.cached.TotalBytes+b.pendingDelta+addBytes > b.hardLimit {
		b.scanLocked()
	}

	check := func() error {
		projected := b.cached.TotalBytes + b.pendingDelta + addBytes
		if b.hardLimit > 0 && projected > b.hardLimit {
			return errWorkdirBudgetExceeded
		}
		floor := b.minFreeDisk
		if priority >= priorityCritical {
			floor = b.criticalFreeDisk
		}
		if b.freeKnown && b.cached.FreeDiskBytes < floor+uint64(addBytes) {
			return errInsufficientDiskSpace
		}
		return nil
	}

	if err := check(); err != nil {
		b.reclaimLocked()
		b.scanLocked()
		if err2 := check(); err2 != nil {
			b.budgetRejects++
			return err2
		}
	}
	b.pendingDelta += addBytes
	return nil
}
