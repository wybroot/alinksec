package guard

import (
	"io/fs"
	"path/filepath"
	"strings"
)

/* 加密速率行为监测（docs/05 §2.1 触发②）：
 * 受监听目录树滑动窗口内快照对比 —— 写入/重命名文件数 > 阈值 且
 * 扩展名变化率 > 比例（加密拖尾典型特征：原名消失 + 加密扩展新文件出现）。
 * 轮询快照实现（免 CGO/免 inotify），窗口 = 轮询周期。 */

const (
	snapMaxDepth   = 5     // 目录树遍历深度上限（防误配打爆）
	snapMaxEntries = 20000 // 单树文件数上限
)

// fileEntry 快照条目：大小 + mtime + 扩展名
type fileEntry struct {
	Size  int64
	Mtime int64
	Ext   string
}

// treeSnapshot 一次目录树快照：path → entry
type treeSnapshot map[string]fileEntry

// rateResult 窗口对比结果
type rateResult struct {
	Modified   []string // 写入（size/mtime 变化）
	Renames    int      // 重命名对数（消失↔新增按 size 精确匹配）
	ExtChanges int      // 重命名中扩展名变化的数量
	Churn      int      // 写入 + 重命名 总量
	Created    []string
	Vanished   []string
}

// matches 触发判定：churn > threshold 且 extChanges/churn > ratio
func (r *rateResult) triggered(threshold int, ratio float64) bool {
	if r.Churn <= threshold || r.Churn == 0 {
		return false
	}
	return float64(r.ExtChanges)/float64(r.Churn) > ratio
}

// snapshotTree 遍历目录树生成快照（限深度/数量；符号链接不跟随）
func snapshotTree(root string) treeSnapshot {
	snap := treeSnapshot{}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == root {
				return err // 根不可读：整树跳过
			}
			return fs.SkipDir // 子目录不可读：跳过该子树
		}
		if d.IsDir() {
			if path != root && strings.HasPrefix(d.Name(), ".") {
				return fs.SkipDir // 隐藏目录跳过（.git 等）
			}
			return nil
		}
		if len(snap) >= snapMaxEntries {
			return fs.SkipAll
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}
		snap[filepath.ToSlash(path)] = fileEntry{
			Size:  info.Size(),
			Mtime: info.ModTime().Unix(),
			Ext:   strings.ToLower(filepath.Ext(path)),
		}
		return nil
	})
	return snap
}

// diffSnapshot 对比前后快照：写入 = 交集内 size/mtime 变化；
// 重命名 = 消失文件按 size 与新增文件配对（勒索加密改名大小不变或相近±16B 头部）
func diffSnapshot(prev, cur treeSnapshot) *rateResult {
	r := &rateResult{}
	created := map[string]fileEntry{} // 新增待配对
	for p, e := range cur {
		if old, ok := prev[p]; ok {
			if e.Size != old.Size || e.Mtime != old.Mtime {
				r.Modified = append(r.Modified, p)
			}
		} else {
			created[p] = e
		}
	}
	used := map[string]bool{}
	for p, old := range prev {
		if _, ok := cur[p]; ok {
			continue
		}
		r.Vanished = append(r.Vanished, p)
		// size 完全相等优先配对；找不到再找 ±16 字节（加密头/填充）
		match := ""
		for c, e := range created {
			if used[c] {
				continue
			}
			if e.Size == old.Size {
				match = c
				break
			}
		}
		if match == "" {
			for c, e := range created {
				if used[c] {
					continue
				}
				d := e.Size - old.Size
				if d < 0 {
					d = -d
				}
				if d <= 16 {
					match = c
					break
				}
			}
		}
		if match != "" {
			used[match] = true
			r.Renames++
			if created[match].Ext != old.Ext {
				r.ExtChanges++
			}
		}
	}
	for c := range created {
		if !used[c] {
			r.Created = append(r.Created, c)
		}
	}
	// churn = 写入 + 重命名（新增未配对不计入：可能是正常落盘）
	r.Churn = len(r.Modified) + r.Renames
	return r
}
