// Periodic metadata snapshots are independent from decoy monitoring.
// Only new or changed files within the declared snapshot/read budgets are checked.
package guard

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alinksec/alinksec-agent/internal/proto"
)

const (
	ruleVirusID   = "PR-0012" // docs/03 内置规则：病毒实时防护
	ruleVirusName = "病毒实时防护"
	virusSweepMax = 200 // 单窗口检查文件数上限（防窗口内海量落盘拖垮 IO）
)

// VirusCheckFunc 单文件检查回调：命中返回 finding（已隔离/告警），干净返回 nil
type VirusCheckFunc func(path string) *proto.VirusFinding

// SetVirusEngine comm 启动时注入（实时防护开关由特征库安装状态天然决定）
func (g *Guard) SetVirusEngine(check VirusCheckFunc) {
	g.mu.Lock()
	g.virusCheck = check
	g.mu.Unlock()
}

func (g *Guard) SetVirusRoots(roots []string, enabled func() bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.virusTrees = append([]string(nil), roots...)
	g.virusEnabled = enabled
	g.virusPrev = map[string]treeSnapshot{}
}
func (g *Guard) virusLoop() {
	g.mu.Lock()
	roots := append([]string(nil), g.virusTrees...)
	enabled := g.virusEnabled
	g.mu.Unlock()
	if enabled != nil && !enabled() {
		return
	}
	var changes []string
	remaining := snapMaxEntries
	deadline := time.Now().Add(2 * time.Second)
	for _, root := range roots {
		if remaining <= 0 || time.Now().After(deadline) {
			break
		}
		current := virusSnapshot(root, &remaining, deadline)
		g.mu.Lock()
		previous, ok := g.virusPrev[root]
		g.virusPrev[root] = current
		g.mu.Unlock()
		if ok {
			diff := diffSnapshot(previous, current)
			changes = append(changes, diff.Modified...)
			changes = append(changes, diff.Created...)
		}
	}
	g.virusSweep(changes)
}

// Read directories in small chunks; budget includes directories and rejected
// entries so a tree of empty directories cannot evade the work limit.
func virusSnapshot(root string, remaining *int, deadline time.Time) treeSnapshot {
	snap := treeSnapshot{}
	var walk func(string, int)
	walk = func(path string, depth int) {
		if depth > snapMaxDepth || *remaining <= 0 || time.Now().After(deadline) {
			return
		}
		*remaining--
		st, err := os.Lstat(path)
		if err != nil || st.Mode()&os.ModeSymlink != 0 {
			return
		}
		if st.Mode().IsRegular() {
			snap[filepath.ToSlash(path)] = fileEntry{Size: st.Size(), Mtime: st.ModTime().UnixNano(), Ext: strings.ToLower(filepath.Ext(path))}
			return
		}
		if !st.IsDir() || depth > 0 && strings.HasPrefix(st.Name(), ".") {
			return
		}
		dir, err := os.Open(path)
		if err != nil {
			return
		}
		defer dir.Close()
		for *remaining > 0 && time.Now().Before(deadline) {
			entries, err := dir.ReadDir(128)
			for _, entry := range entries {
				walk(filepath.Join(path, entry.Name()), depth+1)
			}
			if err != nil {
				break
			}
		}
	}
	walk(root, 0)
	return snap
}

// virusSweep 窗口 diff 文件批量检查：Modified + Created（改名为新路径的加密产物也覆盖）
func (g *Guard) virusSweep(paths []string) {
	g.mu.Lock()
	check := g.virusCheck
	g.mu.Unlock()
	if check == nil || len(paths) == 0 {
		return
	}
	if len(paths) > virusSweepMax {
		paths = paths[:virusSweepMax]
	}
	var hits []*proto.VirusFinding
	deadline := time.Now().Add(2 * time.Second)
	for _, p := range paths {
		if time.Now().After(deadline) {
			break
		}
		if f := check(p); f != nil {
			hits = append(hits, f)
		}
	}
	if len(hits) == 0 {
		return
	}
	// 检出即告警事件（文件已由引擎隔离；不做主机隔离——恶意文件 ≠ 主机失陷）
	for _, f := range hits {
		ev := &proto.RptSecurityEvent{
			RuleId:   ruleVirusID,
			RuleName: ruleVirusName,
			Type:     "virus",
			Severity: f.GetSeverity(),
			Detail: mustJSON(map[string]any{
				"source": "realtime_guard", "name": f.GetName(),
				"path": f.GetPath(), "sha256": f.GetSha256(),
				"action":        f.GetActionTaken(),
				"quarantine_id": f.GetQuarantineId(), "action_error": f.GetActionError(),
				"engine": f.GetEngine(), "size": f.GetSize(), "execution_contract": 2,
			}),
			EventTs: time.Now().UnixMilli(),
		}
		if g.report != nil {
			g.report(ev)
		}
	}
	g.log.Error("实时防护检出恶意文件", "count", len(hits))
}
