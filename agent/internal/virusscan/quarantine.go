// Package virusscan 隔离区（docs/05 §1.4）：
// 移动至本地隔离目录，meta.json 记录原路径 + 哈希，支持人工恢复。
package virusscan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// quarantine 隔离区（进程内无状态：meta.json 即持久化记录）
type quarantine struct {
	dir string
}

// quarantineMeta 隔离记录（文件名 <随机>.meta.json 同名配对）
type quarantineMeta struct {
	OrigPath string `json:"orig_path"`
	QuarFile string `json:"quar_file"`
	Sha256   string `json:"sha256"`
	Size     int64  `json:"size"`
	QuarAt   int64  `json:"quar_at"`
}

// NewQuarantine 创建隔离区操作句柄
func NewQuarantine(workDir string) *quarantine {
	return &quarantine{dir: QuarantineDir(workDir)}
}

// QuarantineFile 隔离文件：rename 至隔离区（同分区零拷贝），meta 落盘。
// Linux 置 0400（root 可恢复，普通用户不可读不可执行）。
func (q *quarantine) QuarantineFile(path string) error {
	if err := os.MkdirAll(q.dir, 0700); err != nil {
		return fmt.Errorf("创建隔离区: %w", err)
	}
	orig, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	st, err := os.Stat(orig)
	if err != nil {
		return err
	}
	// 隔离文件名：时间戳 + 随机后缀防同路径多次隔离冲突
	quarFile := filepath.Join(q.dir, fmt.Sprintf("q%d-%04x", time.Now().UnixMilli(), st.ModTime().UnixNano()&0xffff))
	if err := os.Rename(orig, quarFile); err != nil {
		return fmt.Errorf("移入隔离区: %w", err)
	}
	_ = os.Chmod(quarFile, 0400)

	sum, err := fileSha256(quarFile)
	if err != nil {
		sum = ""
	}
	meta := quarantineMeta{
		OrigPath: orig, QuarFile: quarFile, Sha256: sum,
		Size: st.Size(), QuarAt: time.Now().Unix(),
	}
	b, _ := json.Marshal(meta)
	if err := os.WriteFile(quarFile+".meta.json", b, 0600); err != nil {
		return fmt.Errorf("写隔离记录: %w", err)
	}
	return nil
}

// Restore 恢复：按原路径查 meta → 移回原路径 → 清理记录。
// 原路径已被新文件占用时拒绝恢复（防覆盖）。
func (q *quarantine) Restore(origPath string) error {
	meta, err := q.findMeta(origPath)
	if err != nil {
		return err
	}
	if _, err := os.Stat(meta.OrigPath); err == nil {
		return fmt.Errorf("原路径已存在文件，拒绝覆盖: %s", meta.OrigPath)
	}
	if err := os.MkdirAll(filepath.Dir(meta.OrigPath), 0755); err != nil {
		return fmt.Errorf("重建原目录: %w", err)
	}
	if err := os.Rename(meta.QuarFile, meta.OrigPath); err != nil {
		return fmt.Errorf("移回原路径: %w", err)
	}
	_ = os.Chmod(meta.OrigPath, 0644)
	os.Remove(meta.QuarFile + ".meta.json")
	return nil
}

// Delete 删除处置：优先删原路径（未隔离场景），找不到再找隔离区记录
func (q *quarantine) Delete(path string) error {
	if _, err := os.Stat(path); err == nil {
		return os.Remove(path)
	}
	meta, err := q.findMeta(path)
	if err != nil {
		return err
	}
	if err := os.Remove(meta.QuarFile); err != nil {
		return err
	}
	os.Remove(meta.QuarFile + ".meta.json")
	return nil
}

// findMeta 按原路径/隔离文件路径查隔离记录
func (q *quarantine) findMeta(path string) (*quarantineMeta, error) {
	abs, _ := filepath.Abs(path)
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return nil, fmt.Errorf("读隔离区: %w", err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".meta.json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(q.dir, e.Name()))
		if err != nil {
			continue
		}
		var m quarantineMeta
		if json.Unmarshal(b, &m) == nil && (m.OrigPath == abs || m.QuarFile == path) {
			return &m, nil
		}
	}
	return nil, fmt.Errorf("未找到隔离记录: %s", path)
}
