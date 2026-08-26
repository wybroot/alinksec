package guard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/process"

	"github.com/alinksec/alinksec-agent/internal/proto"
)

/* 触发响应链（docs/05 §2.3，本地立即执行，不依赖服务端在线）：
 * ① 归因（Linux /proc/<pid>/fd 反查；Windows 启发式最近进程）
 * ② kill 涉事进程（含进程链取证）
 * ③ 主机隔离（response=kill_and_isolate 时）
 * ④ 证据快照（进程链 + 变更文件前 100）
 * ⑤ RptSecurityEvent(type=decoy_tamper / ransom_behavior, severity=critical) */

// suspectProc 涉事进程取证（进程五元组 + 父链 + 二进制哈希）
type suspectProc struct {
	Pid     int32  `json:"pid"`
	PPid    int32  `json:"ppid"`
	Exe     string `json:"exe"`
	Cmdline string `json:"cmdline"`
	User    string `json:"user"`
	ExeSHA  string `json:"exe_sha256,omitempty"`
}

// respond 执行响应链，产出安全事件
func (g *Guard) respond(trigger, ruleID, ruleName string, tampered []string, files []string) *proto.RptSecurityEvent {
	c := g.cur()
	detail := map[string]any{
		"trigger":   trigger,
		"timestamp": time.Now().Format(time.RFC3339),
		"response":  c.Response,
	}
	if len(tampered) > 0 {
		detail["decoys"] = tampered
	}

	// ① 归因
	proc := g.attribute(files)
	if proc != nil {
		detail["process"] = proc
		if g.excluded(proc.Exe) {
			// 排除清单命中（备份/杀毒类）：降级为仅告警，避免误杀备份作业
			g.log.Warn("触发进程在排除清单，降级为仅告警", "exe", proc.Exe)
			detail["excluded_exe"] = proc.Exe
			return g.buildEvent(ruleID, ruleName, detail, "alert_only", nil)
		}
	}

	// ② kill
	actionTaken := "alert_only"
	if proc != nil && (c.Response == "kill" || c.Response == "kill_and_isolate") {
		if killed := KillProcess(proc.Pid); killed {
			actionTaken = "killed"
		}
	}

	// ③ 隔离
	if c.Response == "kill_and_isolate" {
		if err := g.IsolateHost("decoy trigger: " + trigger); err != nil {
			g.log.Error("主机隔离失败", "err", err)
			detail["isolate_error"] = err.Error()
		} else {
			if actionTaken == "killed" {
				actionTaken = "killed_and_isolated"
			} else {
				actionTaken = "isolated"
			}
		}
	}

	// ④ 证据：变更文件（前 100）+ 全量进程快照落工作目录
	if len(files) > 100 {
		files = files[:100]
	}
	detail["files"] = files
	var evKeys []string
	if ek := g.dumpEvidence(trigger, proc, files); len(ek) > 0 {
		evKeys = ek
		detail["evidence"] = ek
	}

	return g.buildEvent(ruleID, ruleName, detail, actionTaken, evKeys)
}

// buildEvent 组装上报事件（severity=critical）
func (g *Guard) buildEvent(ruleID, ruleName string, detail map[string]any, action string, evidence []string) *proto.RptSecurityEvent {
	// 类型映射：PR-0010 诱饵篡改 / PR-0011 加密行为
	typ := "ransom_behavior"
	if strings.Contains(ruleID, "PR-0010") {
		typ = "decoy_tamper"
	}
	b, _ := json.Marshal(detail)
	return &proto.RptSecurityEvent{
		RuleId:       ruleID,
		RuleName:     ruleName,
		Type:         typ,
		Severity:     proto.Severity_SEV_CRITICAL,
		Detail:       string(b),
		ActionTaken:  action,
		EventTs:      time.Now().UnixMilli(),
		EvidenceKeys: evidence,
	}
}

// excluded exe 是否命中排除清单（备份/杀毒/索引/同步盘）
func (g *Guard) excluded(exe string) bool {
	if exe == "" {
		return false
	}
	exe = strings.ToLower(exe)
	for _, p := range g.cur().ExcludeExes {
		if p != "" && strings.Contains(exe, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

/* ---- 归因 ---- */

// attribute 反查写入者：优先平台实现（Linux /proc/*/fd），回退最近活跃进程启发式
func (g *Guard) attribute(files []string) *suspectProc {
	if p := attributeByOpenFD(files); p != nil {
		return p
	}
	return attributeByRecency(g.excluded)
}

// takeForensics 采集进程五元组 + 父进程链首层 + exe 哈希
func takeForensics(p *process.Process) *suspectProc {
	sp := &suspectProc{Pid: p.Pid}
	if pp, err := p.Ppid(); err == nil {
		sp.PPid = pp
	}
	if exe, err := p.Exe(); err == nil {
		sp.Exe = exe
		sp.ExeSHA = fileSha256(exe)
	}
	if cl, err := p.CmdlineSlice(); err == nil {
		sp.Cmdline = strings.Join(cl, " ")
	}
	if u, err := p.Username(); err == nil {
		sp.User = u
	}
	return sp
}

// attributeByRecency 启发式：最近 10 分钟启动的非系统进程（Windows/归因失败回退）
func attributeByRecency(excluded func(string) bool) *suspectProc {
	pids, err := process.Pids()
	if err != nil {
		return nil
	}
	cutoff := time.Now().Add(-10 * time.Minute)
	var candidates []*suspectProc
	for _, pid := range pids {
		p, err := process.NewProcess(pid)
		if err != nil {
			continue
		}
		ct, err := p.CreateTime()
		if err != nil || time.UnixMilli(ct).Before(cutoff) {
			continue
		}
		exe, err := p.Exe()
		if err != nil || exe == "" || excluded(exe) {
			continue
		}
		// 系统路径排除：Windows System32 / Linux /usr/lib 等
		l := strings.ToLower(exe)
		if strings.Contains(l, `:\windows\`) || strings.HasPrefix(l, "/usr/lib/") ||
			strings.HasPrefix(l, "/sbin") || strings.HasPrefix(l, "/usr/sbin") {
			continue
		}
		if sp := takeForensics(p); sp.Exe != "" {
			candidates = append(candidates, sp)
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	// 取 pid 最大（通常最新）者
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Pid > candidates[j].Pid })
	return candidates[0]
}

// KillProcess 结束进程树（先杀子再杀父，防重启拉起）；comm 的 CmdProtectAction 复用
func KillProcess(pid int32) bool {
	p, err := process.NewProcess(pid)
	if err != nil {
		return syscallKill(pid) == nil
	}
	if children, err := p.Children(); err == nil {
		for _, ch := range children {
			_ = ch.Kill()
		}
	}
	return p.Kill() == nil
}

// KillByPath 按 exe 路径查杀全部进程，返回击杀数
func KillByPath(exe string) int {
	procs, err := process.Processes()
	if err != nil {
		return 0
	}
	n := 0
	for _, p := range procs {
		if e, err := p.Exe(); err == nil && strings.EqualFold(e, exe) {
			if p.Kill() == nil {
				n++
			}
		}
	}
	return n
}

/* ---- 证据 ---- */

// dumpEvidence 进程链 + 变更文件快照落 evidence/<ts>.json，返回相对 key
func (g *Guard) dumpEvidence(trigger string, proc *suspectProc, files []string) []string {
	ev := map[string]any{
		"trigger": trigger,
		"time":    time.Now().Format(time.RFC3339),
		"files":   files,
	}
	if proc != nil {
		ev["suspect"] = proc
	}
	// 全量进程清单（top CPU/RSS 取证参考）
	if procs, err := process.Processes(); err == nil {
		list := make([]map[string]any, 0, len(procs))
		for _, p := range procs {
			if exe, err := p.Exe(); err == nil && exe != "" {
				list = append(list, map[string]any{"pid": p.Pid, "exe": exe})
			}
		}
		ev["processes"] = list
	}
	b, _ := json.MarshalIndent(ev, "", " ")
	dir := filepath.Join(g.workDir, "evidence")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil
	}
	name := fmt.Sprintf("%s_%d.json", triggerKind(trigger), time.Now().UnixMilli())
	if err := os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
		return nil
	}
	return []string{"evidence/" + name}
}

func triggerKind(trigger string) string {
	if strings.Contains(trigger, "decoy") {
		return "decoy_tamper"
	}
	return "ransom_behavior"
}
