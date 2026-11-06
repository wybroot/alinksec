package guard

import (
	"context"
	"encoding/json"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/process"

	"alinksec-agent/internal/config"
	pb "alinksec-agent/proto"
)

var edrRegexCache sync.Map

func getOrCompileRegex(pattern string) (*regexp.Regexp, error) {
	if val, ok := edrRegexCache.Load(pattern); ok {
		if re, ok := val.(*regexp.Regexp); ok {
			return re, nil
		}
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	edrRegexCache.Store(pattern, re)
	return re, nil
}

const processScanInterval = 2 * time.Second

type processIdentity struct {
	created int64
	exe     string
}

type processObservation struct {
	pid     int32
	created int64
	exe     string
	cmdline string
	user    string
}

func (g *Guard) seedProcessBaseline() {
	g.scanProcesses(false)
}

func (g *Guard) processLoop() {
	g.scanProcesses(true)
}

func (g *Guard) scanProcesses(evaluate bool) {
	procs, err := process.Processes()
	if err != nil {
		g.log.Debug("进程规则枚举失败", "err", err)
		return
	}
	current := make(map[int32]processIdentity, len(procs))
	for _, proc := range procs {
		created, err := proc.CreateTime()
		if err != nil {
			continue
		}
		exe, _ := proc.Exe()
		ident := processIdentity{created: created, exe: exe}
		current[proc.Pid] = ident
		g.mu.Lock()
		previous, seen := g.processSeen[proc.Pid]
		g.processSeen[proc.Pid] = ident
		g.mu.Unlock()
		if seen && previous.created == created && previous.exe == exe {
			continue
		}
		g.evaluateProcessWithActions(proc, created, evaluate)
	}
	g.mu.Lock()
	g.processSeen = current
	g.mu.Unlock()
}

func (g *Guard) evaluateProcess(proc *process.Process, created int64) {
	g.evaluateProcessWithActions(proc, created, true)
}

func (g *Guard) evaluateProcessWithActions(proc *process.Process, created int64, allowActions bool) {
	obs := processObservation{pid: proc.Pid, created: created}
	obs.exe, _ = proc.Exe()
	if args, err := proc.CmdlineSlice(); err == nil {
		obs.cmdline = strings.Join(args, " ")
	}
	obs.user, _ = proc.Username()

	g.mu.Lock()
	rules := append([]config.ProcessRule(nil), g.processRules...)
	g.mu.Unlock()
	for _, rule := range rules {
		if !processRuleMatches(rule, obs) {
			continue
		}
		forensics := takeForensics(proc)
		detail := map[string]any{
			"startup_inventory": !allowActions,
			"process":           forensics,
			"process_key":       fmt.Sprintf("%d:%d", obs.pid, obs.created),
			"match":             map[string]any{"exe": obs.exe, "cmdline": redactCommandLine(strings.Fields(obs.cmdline))},
		}
		if forensics != nil {
			detail["pid_tree"] = forensics.PidTree
			detail["in_container"] = forensics.InContainer
			if forensics.ContainerID != "" {
				detail["container_id"] = forensics.ContainerID
			}
			detail["net_status"] = forensics.NetStatus
		}
		action := "alert_only"
		if allowActions && hasAction(rule.Actions, "kill") && KillProcess(proc.Pid) {
			action = "killed"
		}
		payload, _ := json.Marshal(detail)
		event := &pb.RptSecurityEvent{
			RuleId:      rule.ID,
			RuleName:    rule.Name,
			Type:        "process",
			Severity:    processSeverity(rule.Severity),
			Detail:      string(payload),
			ActionTaken: action,
			EventTs:     time.Now().UnixMilli(),
		}
		g.log.Warn("进程规则命中", "rule", rule.ID, "pid", proc.Pid, "exe", obs.exe, "action", action)
		if g.report != nil {
			g.report(event)
		}
	}
}

func processRuleMatches(rule config.ProcessRule, obs processObservation) bool {
	if !rule.Enabled || rule.ID == "" || (rule.Match.ExeRegex == "" && rule.Match.CmdlineRegex == "") {
		return false
	}
	// R40: 校验目标平台适用性
	if len(rule.Match.Platforms) > 0 {
		matchedPlatform := false
		for _, p := range rule.Match.Platforms {
			if strings.EqualFold(strings.TrimSpace(p), runtime.GOOS) {
				matchedPlatform = true
				break
			}
		}
		if !matchedPlatform {
			return false
		}
	}
	for _, excluded := range rule.Match.UserExclude {
		if strings.EqualFold(strings.TrimSpace(excluded), obs.user) {
			return false
		}
	}
	if rule.Match.ExeRegex != "" {
		re, err := getOrCompileRegex(rule.Match.ExeRegex)
		if err != nil {
			return false
		}
		// R40: 路径分隔符归一化，支持 Windows 反斜杠与 Linux 正斜杠双向匹配
		normalizedExe := filepath.ToSlash(obs.exe)
		if !re.MatchString(obs.exe) && !re.MatchString(normalizedExe) {
			return false
		}
	}
	if rule.Match.CmdlineRegex != "" {
		re, err := getOrCompileRegex(rule.Match.CmdlineRegex)
		if err != nil || !re.MatchString(obs.cmdline) {
			return false
		}
	}
	return true
}

func hasAction(actions []string, want string) bool {
	for _, action := range actions {
		if action == want {
			return true
		}
	}
	return false
}

func processSeverity(level int) pb.Severity {
	if level < 1 {
		return pb.Severity_SEV_HIGH
	}
	if level > 4 {
		level = 4
	}
	// The rule table uses 1=low through 4=critical; protobuf includes INFO.
	return pb.Severity(level + 1)
}
