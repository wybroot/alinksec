package guard

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/process"

	"github.com/alinksec/alinksec-agent/internal/config"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

const processScanInterval = 2 * time.Second

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
		g.log.Debug("EDR 进程枚举失败", "err", err)
		return
	}
	current := make(map[int32]int64, len(procs))
	for _, proc := range procs {
		created, err := proc.CreateTime()
		if err != nil {
			continue
		}
		current[proc.Pid] = created
		g.mu.Lock()
		previous, seen := g.processSeen[proc.Pid]
		g.processSeen[proc.Pid] = created
		g.mu.Unlock()
		if !evaluate || (seen && previous == created) {
			continue
		}
		g.evaluateProcess(proc, created)
	}
	g.mu.Lock()
	g.processSeen = current
	g.mu.Unlock()
}

func (g *Guard) evaluateProcess(proc *process.Process, created int64) {
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
		detail := map[string]any{
			"process":     takeForensics(proc),
			"process_key": fmt.Sprintf("%d:%d", obs.pid, obs.created),
			"match":       map[string]any{"exe": obs.exe, "cmdline": redactCommandLine(strings.Fields(obs.cmdline))},
		}
		action := "alert_only"
		if hasAction(rule.Actions, "kill") && KillProcess(proc.Pid) {
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
		g.log.Warn("EDR 进程规则命中", "rule", rule.ID, "pid", proc.Pid, "exe", obs.exe, "action", action)
		if g.report != nil {
			g.report(event)
		}
	}
}

func processRuleMatches(rule config.ProcessRule, obs processObservation) bool {
	if !rule.Enabled || rule.ID == "" || (rule.Match.ExeRegex == "" && rule.Match.CmdlineRegex == "") {
		return false
	}
	for _, excluded := range rule.Match.UserExclude {
		if strings.EqualFold(strings.TrimSpace(excluded), obs.user) {
			return false
		}
	}
	if rule.Match.ExeRegex != "" {
		re, err := regexp.Compile(rule.Match.ExeRegex)
		if err != nil || !re.MatchString(obs.exe) {
			return false
		}
	}
	if rule.Match.CmdlineRegex != "" {
		re, err := regexp.Compile(rule.Match.CmdlineRegex)
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
