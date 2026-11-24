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
 * ① 归因（Linux 暂无可信写入证据，跳过终止；Windows 内核文件 ETW 与进程实例）
 * ② kill 涉事进程（含进程链取证）
 * ③ 主机隔离（response=kill_and_isolate 时）
 * ④ 证据快照（进程链 + 变更文件前 100）
 * ⑤ RptSecurityEvent(type=decoy_tamper / ransom_behavior, severity=critical) */

// suspectProc 涉事进程取证（进程五元组 + 父链 + 二进制哈希）
type suspectProc struct {
	Pid     int32            `json:"pid"`
	PPid    int32            `json:"ppid"`
	Exe     string           `json:"exe"`
	Cmdline string           `json:"cmdline"`
	User    string           `json:"user"`
	ExeSHA  string           `json:"exe_sha256,omitempty"`
	Lineage []processLineage `json:"lineage,omitempty"`
}

// processLineage is ordered from the implicated process toward init/root.
// It is bounded so evidence collection cannot become unbounded on a host.
type processLineage struct {
	Pid     int32  `json:"pid"`
	PPid    int32  `json:"ppid"`
	Exe     string `json:"exe"`
	Cmdline string `json:"cmdline"`
	User    string `json:"user"`
	ExeSHA  string `json:"exe_sha256,omitempty"`
}

// respond 执行响应链，产出安全事件
func (g *Guard) respond(trigger, ruleID, ruleName string, tampered []string, files []string) *proto.RptSecurityEvent {
	return g.respondSince(trigger, ruleID, ruleName, tampered, files, time.Now().Add(-healthInterval))
}

func (g *Guard) respondSince(trigger, ruleID, ruleName string, tampered []string, files []string, since time.Time) *proto.RptSecurityEvent {
	return g.respondWithAttributionFiles(trigger, ruleID, ruleName, tampered, files, files, since)
}

func (g *Guard) respondWithAttributionFiles(trigger, ruleID, ruleName string, tampered, files, attributionFiles []string, since time.Time) *proto.RptSecurityEvent {
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
	proc, terminate := g.attributeResponse(attributionFiles, since, detail)
	if proc != nil {
		detail["process"] = proc
		if g.excluded(proc.Exe) {
			// 排除清单命中（备份/杀毒类）：降级为仅告警，避免误杀备份作业
			g.log.Warn("触发进程在排除清单，降级为仅告警", "exe", proc.Exe)
			detail["excluded_exe"] = proc.Exe
			c.Response = "alert_only"
		}
	}

	// ② kill
	actionTaken := "alert_only"
	if proc != nil && (c.Response == "kill" || c.Response == "kill_and_isolate") {
		if err := terminate(); err == nil {
			actionTaken = "killed"
		} else {
			detail["kill_error"] = err.Error()
		}
	}

	// ③ 隔离
	if c.Response == "kill_and_isolate" {
		if err := g.IsolateHost("decoy trigger: " + trigger); err != nil {
			g.log.Error("主机隔离失败", "err", err)
			detail["isolate_error"] = err.Error()
		} else {
			if actionTaken == "killed" {
				actionTaken = "killed_isolation_pending"
			} else {
				actionTaken = "isolation_pending"
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

// takeForensics captures the implicated process and up to eight parent
// processes. This keeps the attribution evidence local, bounded, and useful
// for later security investigation.
func takeForensics(p *process.Process) *suspectProc {
	lineage := make([]processLineage, 0, 8)
	seen := make(map[int32]struct{}, 8)
	current := p
	for len(lineage) < 8 && current != nil {
		if _, ok := seen[current.Pid]; ok {
			break
		}
		seen[current.Pid] = struct{}{}
		node := snapshotProcess(current)
		lineage = append(lineage, node)
		if node.PPid <= 0 || node.PPid == current.Pid {
			break
		}
		parent, err := process.NewProcess(node.PPid)
		if err != nil {
			break
		}
		current = parent
	}
	if len(lineage) == 0 {
		return nil
	}
	first := lineage[0]
	return &suspectProc{
		Pid: first.Pid, PPid: first.PPid, Exe: first.Exe, Cmdline: first.Cmdline,
		User: first.User, ExeSHA: first.ExeSHA, Lineage: lineage,
	}
}

func snapshotProcess(p *process.Process) processLineage {
	node := processLineage{Pid: p.Pid}
	if pp, err := p.Ppid(); err == nil {
		node.PPid = pp
	}
	if exe, err := p.Exe(); err == nil {
		node.Exe = exe
		node.ExeSHA = fileSha256(exe)
	}
	if cl, err := p.CmdlineSlice(); err == nil {
		node.Cmdline = redactCommandLine(cl)
	}
	if u, err := p.Username(); err == nil {
		node.User = u
	}
	return node
}

func redactCommandLine(args []string) string {
	redacted := append([]string(nil), args...)
	for i, arg := range redacted {
		name := strings.TrimLeft(strings.SplitN(strings.ToLower(arg), "=", 2)[0], "-")
		name = strings.ReplaceAll(name, "_", "-")
		if !sensitiveArgument(name) {
			continue
		}
		if equals := strings.Index(arg, "="); equals >= 0 {
			redacted[i] = arg[:equals+1] + "***"
		} else if i+1 < len(redacted) {
			redacted[i+1] = "***"
		}
	}
	return strings.Join(redacted, " ")
}

func sensitiveArgument(name string) bool {
	for _, key := range []string{"password", "passwd", "pwd", "token", "secret", "api-key", "apikey", "access-key", "accesskey", "client-secret", "clientsecret", "private-key", "privatekey", "auth", "authorization", "bearer", "cookie"} {
		if name == key || strings.HasSuffix(name, "-"+key) {
			return true
		}
	}
	return false
}

// KillProcess terminates the complete descendant tree before the target so a
// child cannot keep running or immediately recreate its parent.
func KillProcess(pid int32) bool {
	p, err := process.NewProcess(pid)
	if err != nil {
		return syscallKill(pid) == nil
	}
	return killProcessTree(p, map[int32]struct{}{})
}

func killProcessTree(p *process.Process, seen map[int32]struct{}) bool {
	if _, ok := seen[p.Pid]; ok {
		return false
	}
	seen[p.Pid] = struct{}{}
	if children, err := p.Children(); err == nil {
		for _, child := range children {
			_ = killProcessTree(child, seen)
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

const (
	defaultGuardEvidenceFiles     = 200
	defaultGuardEvidenceDirBytes  = 32 << 20
	defaultGuardEvidenceFileBytes = 2 << 20
)

var (
	guardEvidenceMaxFiles           = defaultGuardEvidenceFiles
	guardEvidenceMaxDirBytes  int64 = defaultGuardEvidenceDirBytes
	guardEvidenceMaxFileBytes       = defaultGuardEvidenceFileBytes
)

// dumpEvidence 进程链 + 变更文件快照落 evidence/<ts>.json，受文件数与目录总容量预算约束，返回相对 key
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
	if guardEvidenceMaxFileBytes > 0 && len(b) > guardEvidenceMaxFileBytes {
		delete(ev, "processes")
		ev["processes_omitted"] = true
		b, _ = json.MarshalIndent(ev, "", " ")
	}
	dir := filepath.Join(g.workDir, "evidence")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil
	}
	pruneEvidenceDir(dir, int64(len(b)))

	tmp, err := os.CreateTemp(dir, ".ev-*")
	if err != nil {
		return nil
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(b); err == nil {
		if err = tmp.Sync(); err == nil {
			err = tmp.Close()
		} else {
			_ = tmp.Close()
		}
	} else {
		_ = tmp.Close()
	}
	if err != nil {
		_ = os.Remove(tmpPath)
		return nil
	}

	kind := triggerKind(trigger)
	ts := time.Now().UnixMilli()
	name := fmt.Sprintf("%s_%d.json", kind, ts)
	dst := filepath.Join(dir, name)
	for seq := 1; ; seq++ {
		if _, statErr := os.Lstat(dst); os.IsNotExist(statErr) {
			break
		}
		name = fmt.Sprintf("%s_%d_%d.json", kind, ts, seq)
		dst = filepath.Join(dir, name)
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		_ = os.Remove(tmpPath)
		return nil
	}
	return []string{"evidence/" + name}
}

func pruneEvidenceDir(dir string, incomingBytes int64) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type evFile struct {
		path string
		size int64
		mod  time.Time
	}
	var existing []evFile
	var totalBytes int64
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		existing = append(existing, evFile{
			path: filepath.Join(dir, entry.Name()),
			size: info.Size(),
			mod:  info.ModTime(),
		})
		totalBytes += info.Size()
	}
	sort.Slice(existing, func(i, j int) bool {
		return existing[i].mod.Before(existing[j].mod)
	})
	remaining := len(existing)
	for _, f := range existing {
		needCount := guardEvidenceMaxFiles > 0 && remaining >= guardEvidenceMaxFiles
		needSpace := guardEvidenceMaxDirBytes > 0 && totalBytes+incomingBytes > guardEvidenceMaxDirBytes
		if !needCount && !needSpace {
			break
		}
		if os.Remove(f.path) == nil {
			totalBytes -= f.size
			remaining--
		}
	}
}

func triggerKind(trigger string) string {
	if strings.Contains(trigger, "decoy") {
		return "decoy_tamper"
	}
	return "ransom_behavior"
}
