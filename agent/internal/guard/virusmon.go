// virusmon 病毒实时防护（docs/05 §1.5）：
// 复用速率监测的树快照 diff——新增/修改文件在窗口内做 L1 哈希比对（准实时），
// 检出即隔离 + RptSecurityEvent(type=virus, critical)。
// 引擎由 comm 注入（virusscan.Engine.CheckAndQuarantine），guard 不直接依赖 virusscan 包
// （避免隔离/取证循环依赖；未注入或特征库未安装时静默跳过）。
package guard

import (
	"time"

	"github.com/alinksec/alinksec-agent/internal/proto"
)

const (
	ruleVirusID   = "PR-0012" // docs/03 内置规则：病毒实时防护
	ruleVirusName = "病毒实时防护"
	virusSweepMax = 200       // 单窗口检查文件数上限（防窗口内海量落盘拖垮 IO）
)

// VirusCheckFunc 单文件检查回调：命中返回 finding（已隔离/告警），干净返回 nil
type VirusCheckFunc func(path string) *proto.VirusFinding

// SetVirusEngine comm 启动时注入（实时防护开关由特征库安装状态天然决定）
func (g *Guard) SetVirusEngine(check VirusCheckFunc) {
	g.mu.Lock()
	g.virusCheck = check
	g.mu.Unlock()
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
	for _, p := range paths {
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
			Severity: proto.Severity_SEV_CRITICAL,
			Detail: mustJSON(map[string]any{
				"source": "realtime_guard", "name": f.GetName(),
				"path": f.GetPath(), "sha256": f.GetSha256(),
				"action": f.GetActionTaken(),
			}),
			EventTs: time.Now().UnixMilli(),
		}
		if g.report != nil {
			g.report(ev)
		}
	}
	g.log.Error("实时防护检出恶意文件", "count", len(hits))
}
