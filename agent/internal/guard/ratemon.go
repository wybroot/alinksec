package guard

import (
	"path/filepath"
	"sort"
	"strings"
	"time"
)

/* 加密速率行为监测（docs/05 §2.1 触发②）：
 * 受监听目录树滑动窗口内快照对比 —— 写入/重命名文件数 > 阈值 且
 * 扩展名变化率 > 比例（加密拖尾典型特征：原名消失 + 加密扩展新文件出现）。
 * 文件事件即时检查独立运行；行为判定保留完整窗口快照，避免缩短窗口造成漏判。 */

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

// snapshotMeta 记录快照遍历的完整性与度量（R22 防截断误报）
type snapshotMeta struct {
	Truncated bool          // 是否触发深度、预算或超时截断
	Reason    string        // 截断原因（budget_exhausted, deadline_exceeded, max_depth_exceeded）
	Entries   int           // 成功收录的文件条目数
	Duration  time.Duration // 快照执行耗时
}

// rateResult 窗口对比结果
type rateResult struct {
	Modified   []string // 写入（size/mtime 变化）
	Renames    int      // 重命名对数（消失↔新增按 size 精确匹配）
	ExtChanges int      // 重命名中扩展名变化的数量
	Churn      int      // 写入 + 重命名 总量
	Created    []string
	Vanished   []string
}

// triggered 触发判定 (R61: 防止批量写入稀释，支持改名比率与总 churn 双通道判定)
func (r *rateResult) triggered(threshold int, ratio float64) bool {
	if threshold <= 0 {
		threshold = 3
	}
	if ratio <= 0 {
		ratio = 0.5
	}
	// 针对改名场景直接以 Renames 作为分母，杜绝攻击者大量写入普通文件稀释告警比率
	if r.Renames >= threshold && float64(r.ExtChanges)/float64(r.Renames) >= ratio {
		return true
	}
	// 针对混合型大批量变更活动，兼顾 Churn 总体变动量与扩展名变化比率
	if r.Churn >= threshold && r.ExtChanges >= threshold && float64(r.ExtChanges)/float64(r.Churn) >= ratio*0.5 {
		return true
	}
	return false
}

// snapshotTree 遍历目录树生成快照（限深度/数量；符号链接不跟随）
func snapshotTree(root string) (treeSnapshot, snapshotMeta) {
	remaining := snapMaxEntries
	return virusSnapshot(root, &remaining, time.Now().Add(2*time.Second))
}

// diffSnapshot 对比前后快照：写入 = 交集内 size/mtime 变化；
// 重命名 = 消失文件与新增文件配对（确定性排序，支持同名前缀与 RSA/公钥加密头 0~1024B 动态容差）
func diffSnapshot(prev, cur treeSnapshot) *rateResult {
	r := &rateResult{}
	created := map[string]fileEntry{}
	for p, e := range cur {
		if old, ok := prev[p]; ok {
			if e.Size != old.Size || e.Mtime != old.Mtime {
				r.Modified = append(r.Modified, p)
			}
		} else {
			created[p] = e
		}
	}

	var vanishedKeys []string
	for p := range prev {
		if _, ok := cur[p]; !ok {
			vanishedKeys = append(vanishedKeys, p)
		}
	}
	sort.Strings(vanishedKeys)
	r.Vanished = vanishedKeys

	var createdKeys []string
	for c := range created {
		createdKeys = append(createdKeys, c)
	}
	sort.Strings(createdKeys)

	used := map[string]bool{}
	for _, p := range vanishedKeys {
		old := prev[p]
		pDir := filepath.Dir(p)
		pBase := strings.TrimSuffix(filepath.Base(p), filepath.Ext(p))

		// 1. 优先在同目录下匹配前缀相同的文件（典型勒索追加扩展名，如 docx -> docx.locked），容差支持 1024 字节加密头
		match := ""
		for _, c := range createdKeys {
			if used[c] {
				continue
			}
			if filepath.Dir(c) == pDir && strings.HasPrefix(filepath.Base(c), pBase) {
				e := created[c]
				d := e.Size - old.Size
				if d < 0 {
					d = -d
				}
				if d <= 1024 {
					match = c
					break
				}
			}
		}

		// 2. 次优匹配：大小完全相等（跨目录重命名或非前缀扩展名重命名）
		if match == "" {
			for _, c := range createdKeys {
				if used[c] {
					continue
				}
				if created[c].Size == old.Size {
					match = c
					break
				}
			}
		}

		// 3. 兜底匹配：±1024 字节以内差异（涵盖 RSA/AES 加密公钥与元数据头）
		if match == "" {
			for _, c := range createdKeys {
				if used[c] {
					continue
				}
				d := created[c].Size - old.Size
				if d < 0 {
					d = -d
				}
				if d <= 1024 {
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

	for _, c := range createdKeys {
		r.Created = append(r.Created, c)
	}
	r.Churn = len(r.Modified) + r.Renames
	return r
}
