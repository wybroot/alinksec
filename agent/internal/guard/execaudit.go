package guard

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alinksec/alinksec-agent/internal/config"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/securestate"
)

// This is an optional consumer of administrator-installed audit rules, not an
// audit policy installer. Historical PIDs never authorize process termination.
var auditHeader = regexp.MustCompile(`^(node=\S+ )?type=(SYSCALL|EXECVE|EOE) msg=audit\(([0-9]+\.[0-9]+):([0-9]+)\):\s*(.*)$`)
var auditField = regexp.MustCompile(`(?:^|\s)([A-Za-z0-9_]+)=("(?:[^"\\]|\\.)*"|[^\s]+)`)
var auditArgument = regexp.MustCompile(`^a([0-9]+)$`)

type auditExecPending struct {
	Exe       string         `json:"exe"`
	UID       string         `json:"uid"`
	PID       int32          `json:"pid"`
	Timestamp int64          `json:"timestamp"`
	Key       string         `json:"key"`
	Success   bool           `json:"success"`
	Syscall   bool           `json:"syscall"`
	Argc      int            `json:"argc"`
	Args      map[int]string `json:"args"`
	Invalid   bool           `json:"invalid"`
	Bytes     int            `json:"bytes"`
}
type auditExecState struct {
	Pending map[string]*auditExecPending `json:"pending"`
	Done    []string                     `json:"done"`
}
type auditExecMonitor struct {
	mu      sync.Mutex
	path    string
	state   auditExecState
	invalid bool
	status  string
}

func newAuditExecMonitor(workDir string) *auditExecMonitor {
	dir := filepath.Join(workDir, "process-audit")
	m := &auditExecMonitor{path: filepath.Join(dir, "pending.json"), state: auditExecState{Pending: map[string]*auditExecPending{}}}
	if err := securestate.PrivateDir(dir); err != nil {
		m.invalid = true
		return m
	}
	if err := securestate.ReadJSONLimit(m.path, &m.state, 2<<20); err != nil && !os.IsNotExist(err) {
		m.invalid = true
	}
	if m.state.Pending == nil {
		m.state.Pending = map[string]*auditExecPending{}
	}
	if len(m.state.Pending) > 128 || len(m.state.Done) > 256 {
		m.invalid = true
	}
	for _, p := range m.state.Pending {
		if p == nil || p.Args == nil || len(p.Args) > 256 || p.Bytes > 16384 {
			m.invalid = true
		}
	}
	return m
}
func auditString(value string) (string, bool) {
	if strings.HasPrefix(value, "\"") {
		v, e := strconv.Unquote(value)
		return v, e == nil && !strings.ContainsRune(v, 0)
	}
	b, e := hex.DecodeString(value)
	return string(b), e == nil && !strings.ContainsRune(string(b), 0)
}
func (m *auditExecMonitor) observe(lines []*pb.LogLine, rules []config.ProcessRule) ([]*pb.RptSecurityEvent, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var events []*pb.RptSecurityEvent
	notice := func(status string) {
		if m.status == status {
			return
		}
		m.status = status
		severity := pb.Severity_SEV_MEDIUM
		if status == "reading_unverified" || status == "execution_records_observed" {
			severity = pb.Severity_SEV_INFO
		}
		events = append(events, &pb.RptSecurityEvent{RuleId: "linux-process-audit", RuleName: "Linux 进程审计采集状态", Type: "self_defense", Severity: severity, ActionTaken: "alert_only", EventTs: time.Now().UnixMilli(), Detail: mustJSON(map[string]any{"source": "linux_audit_exec", "status": status, "automatic_kill_supported": false})})
	}
	if m.invalid {
		notice("state_invalid")
		return events, false
	}
	for _, line := range lines {
		if line == nil {
			continue
		}
		if line.GetFields()["record_kind"] == "collection_status" {
			issue := line.GetFields()["status"]
			if issue == "reading" {
				notice("reading_unverified")
			} else {
				m.state.Pending = map[string]*auditExecPending{}
				notice("source_unavailable_or_gap")
			}
			continue
		}
		if line.GetFields()["truncated"] == "true" || len(line.Content) > 16384 {
			m.state.Pending = map[string]*auditExecPending{}
			notice("truncated_event_gap")
			continue
		}
		h := auditHeader.FindStringSubmatch(line.Content)
		if h == nil {
			continue
		}
		id := h[1] + h[3] + ":" + h[4]
		seen := false
		for _, done := range m.state.Done {
			if done == id {
				seen = true
				break
			}
		}
		if seen {
			continue
		}
		p := m.state.Pending[id]
		if p == nil {
			if len(m.state.Pending) >= 128 {
				m.state.Pending = map[string]*auditExecPending{}
				notice("pending_capacity_gap")
			}
			seconds, err := strconv.ParseFloat(h[3], 64)
			if err != nil || seconds <= 0 || seconds > float64(time.Now().Unix()+30) {
				continue
			}
			p = &auditExecPending{Timestamp: int64(seconds * 1000), Argc: -1, Args: map[int]string{}}
			m.state.Pending[id] = p
		}
		fields := map[string]string{}
		for _, field := range auditField.FindAllStringSubmatch(h[5], -1) {
			if _, exists := fields[field[1]]; exists {
				p.Invalid = true
			}
			fields[field[1]] = field[2]
		}
		switch h[2] {
		case "SYSCALL":
			if p.Syscall {
				p.Invalid = true
			}
			p.Syscall = true
			p.Key, _ = auditString(fields["key"])
			p.Exe, _ = auditString(fields["exe"])
			pid, err := strconv.ParseInt(fields["pid"], 10, 32)
			if err != nil || pid <= 0 {
				p.Invalid = true
			}
			p.PID = int32(pid)
			if _, err := strconv.ParseUint(fields["uid"], 10, 32); err != nil {
				p.Invalid = true
			}
			p.UID = fields["uid"]
			p.Success = fields["success"] == "yes"
		case "EXECVE":
			if value, ok := fields["argc"]; ok {
				argc, err := strconv.Atoi(value)
				if err != nil || argc < 1 || argc > 256 || (p.Argc != -1 && p.Argc != argc) {
					p.Invalid = true
				}
				p.Argc = argc
			}
			for name, value := range fields {
				match := auditArgument.FindStringSubmatch(name)
				if match == nil {
					if strings.HasPrefix(name, "a") && name != "argc" {
						p.Invalid = true
					}
					continue
				}
				index, err := strconv.Atoi(match[1])
				if err != nil || index > 255 {
					p.Invalid = true
					continue
				}
				arg, ok := auditString(value)
				if !ok {
					p.Invalid = true
					continue
				}
				if _, exists := p.Args[index]; exists {
					p.Invalid = true
					continue
				}
				p.Bytes += len(arg)
				if p.Bytes > 16384 {
					p.Invalid = true
					continue
				}
				p.Args[index] = arg
			}
		}
		// Some audit logs omit EOE. Once the syscall and all argv fields are
		// present, the evidence needed for alert-only matching is complete.
		if h[2] == "EOE" || (p.Syscall && p.Argc > 0 && len(p.Args) == p.Argc) {
			delete(m.state.Pending, id)
			if p.Key != "alinksec_exec" {
				continue
			}
			m.state.Done = append(m.state.Done, id)
			if len(m.state.Done) > 256 {
				m.state.Done = m.state.Done[len(m.state.Done)-256:]
			}
			if p.Invalid || !p.Syscall || p.Exe == "" || p.Argc < 1 || len(p.Args) != p.Argc {
				notice("incomplete_execution_event")
				continue
			}
			args := make([]string, p.Argc)
			complete := true
			for i := range args {
				value, ok := p.Args[i]
				if !ok {
					complete = false
					break
				}
				args[i] = value
			}
			if !complete {
				notice("incomplete_execution_event")
				continue
			}
			if !p.Success {
				continue
			}
			notice("execution_records_observed")
			username := p.UID
			if account, err := user.LookupId(p.UID); err == nil {
				username = account.Username
			}
			obs := processObservation{pid: p.PID, exe: p.Exe, cmdline: strings.Join(args, " "), user: username}
			for _, rule := range rules {
				if !processRuleMatches(rule, obs) {
					continue
				}
				detail, _ := json.Marshal(map[string]any{"source": "linux_audit_exec", "audit_event_id": id, "process_key": "audit:" + id, "pid": p.PID, "exe": p.Exe, "user": username, "cmdline": redactCommandLine(args), "response_skipped": "historical_pid_not_a_live_process_identity"})
				events = append(events, &pb.RptSecurityEvent{RuleId: rule.ID, RuleName: rule.Name, Type: "process", Severity: processSeverity(rule.Severity), ActionTaken: "alert_only", EventTs: p.Timestamp, Detail: string(detail)})
			}
		}
	}
	if err := securestate.WriteJSONLimit(m.path, m.state, 2<<20); err != nil {
		notice("state_write_failed")
		m.invalid = true
		return events, false
	}
	return events, true
}

func (g *Guard) ObserveProcessAudit(lines []*pb.LogLine) bool {
	g.mu.Lock()
	if g.execAudit == nil {
		g.execAudit = newAuditExecMonitor(g.workDir)
	}
	monitor := g.execAudit
	rules := append([]config.ProcessRule(nil), g.processRules...)
	reportFn := g.report
	g.mu.Unlock()
	events, ok := monitor.observe(lines, rules)
	if !ok {
		return false
	}
	for _, event := range events {
		if reportFn != nil {
			reportFn(event)
		}
	}
	return true
}
