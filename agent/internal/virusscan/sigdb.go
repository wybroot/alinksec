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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// HashEntry 单条哈希情报
type HashEntry struct {
	Name     string // 检出名，如 Trojan.Linux.Miner.X
	Severity int32  // 1-5（proto Severity）
}

// SigDB 内存态特征库
type SigDB struct {
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
	dbOnce   sync.Once
	dbCached *SigDB
	dbPath   string
)

// LoadDB 加载特征库到内存（进程内单例：特征库更新后调 ReloadDB 失效重载）
func LoadDB(workDir string) *SigDB {
	dbOnce.Do(func() {
		dbPath = DBDir(workDir)
		dbCached = parseDB(dbPath)
	})
	return dbCached
}

// ReloadDB 特征库更新后重载（next 单例重建）
func ReloadDB(workDir string) *SigDB {
	dbOnce = sync.Once{}
	return LoadDB(workDir)
}

// parseDB 解析 hashes.txt + manifest.json（损坏时返回空库，不报错：断网沿用旧库语义）
func parseDB(dir string) *SigDB {
	db := &SigDB{hashes: map[string]HashEntry{}}
	if b, err := os.ReadFile(filepath.Join(dir, "manifest.json")); err == nil {
		var m dbManifest
		if json.Unmarshal(b, &m) == nil {
			db.Version, db.HashCount, db.RuleCount = m.DbVersion, m.HashCount, m.RuleCount
		}
	}
	db.rules = parseRules(dir)
	if len(db.rules) > 0 && db.RuleCount == 0 {
		db.RuleCount = len(db.rules)
	}
	f, err := os.Open(filepath.Join(dir, "hashes.txt"))
	if err != nil {
		return db
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for s.Scan() {
		// 行格式：sha256 threat_name severity（threat_name 不含空格）
		p := strings.Fields(s.Text())
		if len(p) < 2 || len(p[0]) != 64 {
			continue
		}
		sev := int32(4) // 缺省高危
		if len(p) >= 3 {
			if v, err := strconv.Atoi(p[2]); err == nil && v >= 1 && v <= 5 {
				sev = int32(v)
			}
		}
		db.hashes[strings.ToLower(p[0])] = HashEntry{Name: p[1], Severity: sev}
	}
	if db.HashCount == 0 {
		db.HashCount = len(db.hashes)
	}
	return db
}

// InstallDB 安装特征库包：sha256 校验 → 解压到临时目录 → 原子替换 db 目录。
// 失败保留旧库（断网沿用本地库）。
func InstallDB(workDir, pkgPath, expectSha256 string) error {
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
	tmp := dbDir + ".tmp"
	if err := os.RemoveAll(tmp); err != nil {
		return fmt.Errorf("清理临时目录: %w", err)
	}
	if err := os.MkdirAll(tmp, 0700); err != nil {
		return fmt.Errorf("创建临时目录: %w", err)
	}
	// 解压（仅接受白名单文件名，防 zip 路径穿越）
	allowed := map[string]bool{"manifest.json": true, "hashes.txt": true, "rules.json": true}
	for _, f := range zr.File {
		name := filepath.Clean(f.Name)
		if !allowed[name] || f.FileInfo().IsDir() {
			continue
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
		if _, err := out.ReadFrom(rc); err != nil {
			rc.Close()
			out.Close()
			return fmt.Errorf("写 %s: %w", name, err)
		}
		rc.Close()
		out.Close()
	}
	// manifest 必须存在（校验解压完整）
	if _, err := os.Stat(filepath.Join(tmp, "manifest.json")); err != nil {
		os.RemoveAll(tmp)
		return fmt.Errorf("特征包缺少 manifest.json")
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
