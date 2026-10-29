package guard

import (
	"encoding/json"
	"github.com/alinksec/alinksec-agent/internal/config"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/shirou/gopsutil/v3/process"
	"io"
	"log/slog"
	"os"
	"regexp"
	"testing"
)

func TestExistingProcessEvaluatedWithoutAutomaticKill(t *testing.T) {
	p, err := process.NewProcess(int32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	exe, err := p.Exe()
	if err != nil {
		t.Fatal(err)
	}
	created, err := p.CreateTime()
	if err != nil {
		t.Fatal(err)
	}
	var events []*pb.RptSecurityEvent
	g := &Guard{log: slog.New(slog.NewTextHandler(io.Discard, nil)), report: func(e *pb.RptSecurityEvent) { events = append(events, e) }, processRules: []config.ProcessRule{{ID: "fixture", Enabled: true, Actions: []string{"kill"}, Match: config.ProcessMatch{ExeRegex: "^" + regexp.QuoteMeta(exe) + "$"}}}}
	g.evaluateProcessWithActions(p, created, false)
	if len(events) != 1 || events[0].ActionTaken != "alert_only" {
		t.Fatalf("startup outcome: %v", events)
	}
	var detail map[string]any
	if err := json.Unmarshal([]byte(events[0].Detail), &detail); err != nil || detail["startup_inventory"] != true {
		t.Fatalf("missing startup evidence: %s", events[0].Detail)
	}
}
