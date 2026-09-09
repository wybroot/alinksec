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
