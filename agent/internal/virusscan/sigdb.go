// Package virusscan 病毒查杀引擎（docs/05 §1）：
// L1 哈希情报层（纯 Go，零依赖）：SHA256 精确匹配特征库；
// L2 YARA 规则层：M3 接入（CGO 构建标签降级方案保留），当前 hash-only。
//
// 特征库包格式（zip，全量包 < 20MB）：
//
//	manifest.json  {"db_version":"20260825001","hash_count":N,"rule_count":0,"sha256":"包自身sha256"}
//	hashes.txt     每行 "sha256 threat_name severity"（空格分隔）
//
// Agent 本地目录布局（workDir 下）：
//
//	virus/db/hashes.txt   当前生效哈希库
//	virus/db/manifest.json
//	virus/quarantine/     隔离区（meta.json 记录原路径）
//	virus/cache.json      clean 缓存（path+size+mtime 未变跳过）
package virusscan

import (
	"archive/zip"
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// HashEntry 单条哈希情报
type HashEntry struct {
	Name     string // 检出名，如 Trojan.Linux.Miner.X
	Severity int32  // 1-5（proto Severity）
}

// SigDB 内存态特征库
type SigDB struct {
	Valid     bool
	Version   string
	HashCount int
	RuleCount int
	hashes    map[string]HashEntry
	rules     []*Rule // L2 YARA 规则层（rules.json）
}

// Lookup 哈希查询
func (d *SigDB) Lookup(sha256 string) (HashEntry, bool) {
	if d == nil || d.hashes == nil {
		return HashEntry{}, false
	}
	e, ok := d.hashes[strings.ToLower(sha256)]
	return e, ok
}

// dbManifest manifest.json 结构
type dbManifest struct {
	DbVersion string `json:"db_version"`
	HashCount int    `json:"hash_count"`
	RuleCount int    `json:"rule_count"`
	Sha256    string `json:"sha256"`
}

// DBDir 特征库目录（workDir/virus/db）
func DBDir(workDir string) string { return filepath.Join(workDir, "virus", "db") }

// QuarantineDir 隔离区目录（workDir/virus/quarantine）
func QuarantineDir(workDir string) string { return filepath.Join(workDir, "virus", "quarantine") }

// LocalVersion 当前本地特征库版本（未安装返回空串）
func LocalVersion(workDir string) string {
	b, err := os.ReadFile(filepath.Join(DBDir(workDir), "manifest.json"))
	if err != nil {
		return ""
	}
	var m dbManifest
	if json.Unmarshal(b, &m) != nil {
		return ""
	}
	return m.DbVersion
}

var (
	dbMu         sync.Mutex
	dbCached     *SigDB
	dbPath       string
	dbGeneration uint64
)

// LoadDB 加载特征库到内存（进程内单例：特征库更新后调 ReloadDB 失效重载）
func LoadDB(workDir string) *SigDB {
	dbMu.Lock()
	defer dbMu.Unlock()
	if dbCached == nil || !dbCached.Valid || dbPath != DBDir(workDir) {
		dbPath = DBDir(workDir)
		dbCached = parseDB(dbPath)
		dbGeneration++
	}
	return dbCached
}

// ReloadDB 特征库更新后重载（next 单例重建）
func ReloadDB(workDir string) *SigDB {
	dbMu.Lock()
	defer dbMu.Unlock()
	dbPath = DBDir(workDir)
	dbCached = parseDB(dbPath)
	dbGeneration++
	return dbCached
}

// Observe the already loaded immutable cache, without loading or reloading
// files. Another work directory or an oversized inventory remains unknown.
func CachedHashSnapshot(ctx context.Context, workDir string, limit int) (string, int, int, map[string]HashEntry, uint64, bool) {
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !dbMu.TryLock() {
		select {
		case <-ctx.Done():
			return "", 0, 0, nil, 0, false
		case <-tick.C:
		}
	}
	defer dbMu.Unlock()
	if ctx.Err() != nil {
		return "", 0, 0, nil, 0, false
	}
	if dbCached == nil || !dbCached.Valid || dbPath != DBDir(workDir) || limit < 1 || len(dbCached.hashes) > limit {
		return "", 0, 0, nil, 0, false
	}
	entries := make(map[string]HashEntry, len(dbCached.hashes))
	for key, value := range dbCached.hashes {
		entries[key] = value
	}
	rules := dbCached.RuleCount
	if len(dbCached.rules) > rules {
		rules = len(dbCached.rules)
	}
	return dbCached.Version, dbCached.HashCount, rules, entries, dbGeneration, true
}

// parseDB 解析 hashes.txt + manifest.json（损坏时返回空库，不报错：断网沿用旧库语义）
func parseDB(dir string) *SigDB {
	db := &SigDB{hashes: map[string]HashEntry{}}
	data, err := boundedFile(filepath.Join(dir, "manifest.json"), 64<<10)
	if err != nil {
		return db
	}
	var manifest dbManifest
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &manifest) != nil || json.Unmarshal(data, &fields) != nil || !signatureVersion.MatchString(manifest.DbVersion) || manifest.HashCount < 0 || manifest.HashCount > maxHashEntries || manifest.RuleCount < 0 || manifest.RuleCount > 2000 {
		return db
	}
	db.Version = manifest.DbVersion
	rules, err := readRuleFile(dir)
	if err != nil {
		return db
	}
	db.rules = rules
	if _, ok := fields["rule_count"]; ok && manifest.RuleCount != len(rules) {
		return db
	}
	f, parent, err := openRegular(filepath.Join(dir, "hashes.txt"), false)
	if err != nil {
		return db
	}
	defer f.Close()
	defer parent.Close()
	info, err := f.Stat()
	if err != nil || info.Size() > maxExpandedBytes {
		return db
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 4096)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 || len(parts) > 3 || len(parts[0]) != 64 || !utf8.ValidString(parts[1]) || utf8.RuneCountInString(parts[1]) > 255 {
			return db
		}
		if _, err := hex.DecodeString(parts[0]); err != nil {
			return db
		}
		severity := 4
		if len(parts) == 3 {
			value, err := strconv.Atoi(parts[2])
			if err != nil || value < 1 || value > 5 {
				return db
			}
			severity = value
		}
		key := strings.ToLower(parts[0])
		if _, duplicate := db.hashes[key]; duplicate {
			return db
		}
		db.hashes[key] = HashEntry{Name: parts[1], Severity: int32(severity)}
		if len(db.hashes) > maxHashEntries {
			return db
		}
	}
	if scanner.Err() != nil {
		return db
	}
	if _, ok := fields["hash_count"]; ok && manifest.HashCount != len(db.hashes) {
		return db
	}
	db.HashCount = len(db.hashes)
	db.RuleCount = len(rules)
	db.Valid = true
	return db
}

var installMu sync.Mutex

// InstallDB 安装特征库包：sha256 校验 → 解压到临时目录 → 原子替换 db 目录。
// 失败保留旧库（断网沿用本地库）。
func InstallDB(workDir, pkgPath, expectSha256 string) error {
	installMu.Lock()
	defer installMu.Unlock()
	if info, err := os.Stat(pkgPath); err != nil || info.Size() > 20<<20 {
		return fmt.Errorf("signature package exceeds 20MiB or is unreadable")
	}
	// 包完整性校验
	got, err := fileSha256(pkgPath)
	if err != nil {
		return fmt.Errorf("读取特征包: %w", err)
	}
	if expectSha256 != "" && !strings.EqualFold(got, expectSha256) {
		return fmt.Errorf("特征包 sha256 不匹配: expect=%s got=%s", expectSha256, got)
	}
	zr, err := zip.OpenReader(pkgPath)
	if err != nil {
		return fmt.Errorf("打开特征包: %w", err)
	}
	defer zr.Close()

	dbDir := DBDir(workDir)
	if err := os.MkdirAll(filepath.Dir(dbDir), 0700); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(filepath.Dir(dbDir), "db.install-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	// 解压（仅接受白名单文件名，防 zip 路径穿越）
	allowed := map[string]bool{"manifest.json": true, "hashes.txt": true, "rules.json": true}
	if len(zr.File) > 3 {
		return fmt.Errorf("unexpected package entries")
	}
	seen := map[string]bool{}
	remaining := maxExpandedBytes
	for _, f := range zr.File {
		name := f.Name
		if !allowed[name] || seen[name] || f.FileInfo().IsDir() || f.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("invalid or duplicate package entry")
		}
		seen[name] = true
		if f.UncompressedSize64 > uint64(remaining) {
			return fmt.Errorf("expanded package exceeds 64MiB")
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("解压 %s: %w", name, err)
		}
		out, err := os.OpenFile(filepath.Join(tmp, name), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			rc.Close()
			return fmt.Errorf("写 %s: %w", name, err)
		}
		n, copyErr := io.Copy(out, io.LimitReader(rc, remaining+1))
		if copyErr != nil || n > remaining {
			rc.Close()
			out.Close()
			return fmt.Errorf("expanded package exceeds limit or cannot be read: %s", name)
		}
		remaining -= n
		rc.Close()
		out.Close()
	}
	// manifest 必须存在（校验解压完整）
	if _, err := os.Stat(filepath.Join(tmp, "manifest.json")); err != nil {
		os.RemoveAll(tmp)
		return fmt.Errorf("特征包缺少 manifest.json")
	}
	if err := validateInstalledDB(tmp); err != nil {
		return err
	}
	// 原子替换：旧目录 → .old，tmp → db，删 .old
	old := dbDir + ".old"
	os.RemoveAll(old)
	if err := os.Rename(dbDir, old); err != nil && !os.IsNotExist(err) {
		os.RemoveAll(tmp)
		return fmt.Errorf("备份旧库: %w", err)
	}
	if err := os.Rename(tmp, dbDir); err != nil {
		if os.Rename(old, dbDir) == nil { // 回滚旧库
			return fmt.Errorf("启用新库: %w（已回滚旧库）", err)
		}
		return fmt.Errorf("启用新库: %w", err)
	}
	os.RemoveAll(old)
	return nil
}
