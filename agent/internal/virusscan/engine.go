// Package virusscan 引擎：遍历扫描 + SHA256 比对 + clean 缓存 + IO 限速。
package virusscan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

// maxFileSize 超限大文件跳过（docs/05 §1.3：默认 >500MB 跳过）
const maxFileSize = 500 << 20

// ioLimitRate 扫描 IO 限速（docs/05：默认 10MB/s，保护业务盘）
const ioLimitRate = 10 << 20

// cacheMaxEntries clean 缓存条目上限（防内存无界增长）
const cacheMaxEntries = 200_000

// cacheEntry clean 缓存条目：path+size+mtime 未变 → 跳过哈希计算
type cacheEntry struct {
	Size   int64 `json:"s"`
	ModSec int64 `json:"m"`
}

// Engine 扫描引擎（无状态，每次任务独立实例；缓存跨任务复用由 LoadCache/SaveCache 承担）
type Engine struct {
	db    *SigDB
	cache map[string]cacheEntry
	log   *slog.Logger
}

// NewEngine 创建引擎并加载 clean 缓存
func NewEngine(workDir string, log *slog.Logger) *Engine {
	return &Engine{
		db:    LoadDB(workDir),
		cache: loadCache(workDir),
		log:   log,
	}
}

// Scan 执行扫描：mode QUICK/FULL/CUSTOM；paths 仅 CUSTOM 生效。
// 检出默认隔离（docs/05 §1.4：隔离为默认动作）。
func (e *Engine) Scan(taskID string, mode pb.CmdVirusScan_Mode, paths []string, workDir string) *pb.RptVirusResult {
	result := &pb.RptVirusResult{TaskId: taskID, Mode: rptMode(mode)}
	start := time.Now()

	var roots []string
	switch mode {
	case pb.CmdVirusScan_FULL:
		roots = fullScanRoots()
	case pb.CmdVirusScan_CUSTOM:
		roots = paths
	default: // QUICK
		roots = quickScanRoots()
	}
	// 特征库未安装（无哈希且无规则）：空跑记录 0 文件（服务端据此提示导入特征库）
	if e.db == nil || (len(e.db.hashes) == 0 && len(e.db.rules) == 0) {
		e.log.Warn("特征库未安装，跳过扫描", "local_version", LocalVersion(workDir))
		result.DurationMs = uint32(time.Since(start).Milliseconds())
		return result
	}

	q := NewQuarantine(workDir)
	for _, root := range roots {
		if root == "" {
			continue
		}
		e.walk(root, result, q)
	}
	result.DurationMs = uint32(time.Since(start).Milliseconds())
	saveCache(workDir, e.cache, e.log)
	e.log.Info("病毒扫描完成", "task", taskID, "mode", mode.String(),
		"files", result.GetFilesScanned(), "findings", len(result.GetFindings()),
		"duration", time.Since(start).Round(time.Millisecond))
	return result
}

// walk 遍历目录树（符号链接不跟随，防环）
func (e *Engine) walk(root string, result *pb.RptVirusResult, q *quarantine) {
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // 无权限/已删除：跳过继续
		}
		if d.IsDir() {
			if isExcludedDir(path) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type() != 0 { // 符号链接/设备文件等非普通文件
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxFileSize || info.Size() == 0 {
			return nil
		}
		result.FilesScanned++

		// clean 缓存命中：内容未变直接跳过
		key := strings.ToLower(path)
		if c, ok := e.cache[key]; ok && c.Size == info.Size() && c.ModSec == info.ModTime().Unix() {
			return nil
		}
		sum, err := hashFileLimited(path)
		if err != nil {
			return nil
		}
		if entry, hit := e.db.Lookup(sum); hit {
			finding := &pb.VirusFinding{
				Path: path, Name: entry.Name, Sha256: sum,
				Size: uint64(info.Size()), Engine: "hash", Severity: pb.Severity(entry.Severity),
			}
			// 默认处置：隔离（失败降级 alert_only，不阻断扫描）
			if err := q.QuarantineFile(path); err != nil {
				e.log.Error("隔离失败，仅告警", "path", path, "err", err)
				finding.ActionTaken = "alert_only"
			} else {
				finding.ActionTaken = "quarantined"
				e.log.Warn("检出恶意文件并隔离", "path", path, "name", entry.Name)
			}
			result.Findings = append(result.Findings, finding)
			return nil
		}
		// L1 未命中 → L2 规则层（docs/05 §1.1：仅 PE/ELF/脚本/office 类且 < 50MB）
		if r := matchRules(e.db.rules, path, info.Size(), readHeadLimited(path)); r != nil {
			finding := &pb.VirusFinding{
				Path: path, Name: r.Name, Sha256: sum,
				Size: uint64(info.Size()), Engine: "rule", Severity: pb.Severity(r.Severity),
			}
			if err := q.QuarantineFile(path); err != nil {
				e.log.Error("L2 检出隔离失败，仅告警", "path", path, "err", err)
				finding.ActionTaken = "alert_only"
			} else {
				finding.ActionTaken = "quarantined"
				e.log.Warn("L2 规则检出并隔离", "path", path, "rule", r.Name)
			}
			result.Findings = append(result.Findings, finding)
			return nil
		}
		// 干净文件进缓存（上限淘汰：简单随机丢弃一半）
		if len(e.cache) >= cacheMaxEntries {
			e.dropHalfCache()
		}
		e.cache[key] = cacheEntry{Size: info.Size(), ModSec: info.ModTime().Unix()}
		return nil
	})
}

// dropHalfCache 缓存满时随机丢弃一半（FIFO 需额外队列，随机足够）
func (e *Engine) dropHalfCache() {
	drop := false
	for k := range e.cache {
		if drop {
			delete(e.cache, k)
		}
		drop = !drop
	}
}

// CheckAndQuarantine 单文件检查（实时防护用，docs/05 §1.5）：
// 大小过滤 → clean 缓存 → L1 哈希 → L2 规则（可扫描扩展且 < 50MB）→ 命中默认隔离。
// 与 walk 共用 db/cache；线程安全由调用侧（单 goroutine 周期触发）保证。
func (e *Engine) CheckAndQuarantine(path, workDir string) *pb.VirusFinding {
	if e.db == nil || (len(e.db.hashes) == 0 && len(e.db.rules) == 0) {
		return nil // 特征库未安装：实时防护静默跳过
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() > maxFileSize || info.Size() == 0 || !info.Mode().IsRegular() {
		return nil
	}
	key := strings.ToLower(path)
	if c, ok := e.cache[key]; ok && c.Size == info.Size() && c.ModSec == info.ModTime().Unix() {
		return nil
	}
	sum, err := hashFileLimited(path)
	if err != nil {
		return nil
	}
	entry, hit := e.db.Lookup(sum)
	engine, name, severity := "hash", entry.Name, entry.Severity
	if !hit {
		// L1 未命中 → L2 规则层
		r := matchRules(e.db.rules, path, info.Size(), readHeadLimited(path))
		if r == nil {
			if len(e.cache) >= cacheMaxEntries {
				e.dropHalfCache()
			}
			e.cache[key] = cacheEntry{Size: info.Size(), ModSec: info.ModTime().Unix()}
			return nil
		}
		engine, name, severity = "rule", r.Name, r.Severity
	}
	finding := &pb.VirusFinding{
		Path: path, Name: name, Sha256: sum,
		Size: uint64(info.Size()), Engine: engine, Severity: pb.Severity(severity),
	}
	if err := NewQuarantine(workDir).QuarantineFile(path); err != nil {
		e.log.Error("实时防护隔离失败，仅告警", "path", path, "err", err)
		finding.ActionTaken = "alert_only"
	} else {
		finding.ActionTaken = "quarantined"
		e.log.Warn("实时防护检出恶意文件并隔离", "path", path, "name", entry.Name)
	}
	return finding
}

// isExcludedDir 全盘扫描排除目录（虚拟文件系统 / Agent 自身目录）
func isExcludedDir(path string) bool {
	p := filepath.ToSlash(strings.ToLower(path))
	switch runtime.GOOS {
	case "windows":
		return strings.HasSuffix(p, "/windows/system32/drivers") // 驱动目录误杀风险高
	default:
		for _, d := range []string{"/proc", "/sys", "/dev", "/run", "/var/lib/docker", "/.snapshots"} {
			if p == d || strings.HasPrefix(p, d+"/") {
				return true
			}
		}
	}
	return false
}

// hashFileLimited 计算文件 SHA256（IO 限速：令牌桶简化为按块 sleep）
func hashFileLimited(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 1<<20)
	read := int64(0)
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
			read += int64(n)
			// 每 10MB 停 1s（10MB/s 限速）
			if chunk := read / ioLimitRate; chunk > 0 && read%ioLimitRate < int64(n) {
				time.Sleep(time.Second)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return "", rerr
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// fileSha256 全速计算（特征包校验用，不走扫描限速）
func fileSha256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

/* ==================== clean 缓存持久化 ==================== */

func cachePath(workDir string) string { return filepath.Join(workDir, "virus", "cache.json") }

func loadCache(workDir string) map[string]cacheEntry {
	b, err := os.ReadFile(cachePath(workDir))
	if err != nil {
		return map[string]cacheEntry{}
	}
	var c map[string]cacheEntry
	if json.Unmarshal(b, &c) != nil {
		return map[string]cacheEntry{}
	}
	return c
}

func saveCache(workDir string, c map[string]cacheEntry, log *slog.Logger) {
	if len(c) == 0 {
		return
	}
	b, err := json.Marshal(c)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(cachePath(workDir)), 0700); err != nil {
		return
	}
	// 临时文件 + 原子替换（扫描中断不留半截缓存）
	tmp := cachePath(workDir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return
	}
	if err := os.Rename(tmp, cachePath(workDir)); err != nil {
		log.Debug("clean 缓存写入失败", "err", err)
	}
}

// rptMode 指令模式 → 上报模式
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
