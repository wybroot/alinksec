//go:build windows

package guard

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/alinksec/alinksec-agent/internal/filetrace"
	"github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/shirou/gopsutil/v3/process"
)

func (g *Guard) runAttribution(ctx context.Context) { go g.fileTrace.Run(ctx) }
func (g *Guard) reportAttributionStatus() {
	r := g.fileTrace.Status()
	key := r.Status + ":" + r.Reason
	g.mu.Lock()
	changed := g.traceStatus != key
	g.traceStatus = key
	g.mu.Unlock()
	if changed {
		g.log.Info("Windows 勒索归因采集状态", "status", r.Status, "reason", r.Reason)
		severity := proto.Severity_SEV_INFO
		if r.Status == "unavailable" {
			severity = proto.Severity_SEV_MEDIUM
		}
		if g.report != nil {
			g.report(&proto.RptSecurityEvent{RuleId: "windows-ransom-attribution", RuleName: "Windows 勒索归因采集", Type: "self_defense", Severity: severity, ActionTaken: "alert_only", Detail: mustJSON(map[string]any{"attribution": r}), EventTs: time.Now().UnixMilli()})
		}
	}
}

func (g *Guard) configureAttribution() {
	c := g.cur()
	var roots []string
	if c.Enabled == nil || *c.Enabled {
		roots = append(roots, g.deployDirs()...)
		roots = append(roots, c.WatchTrees...)
	}
	g.fileTrace.Configure(roots, time.Duration(c.RateWindowSec)*time.Second)
	g.mu.Lock()
	g.healthSince = time.Now()
	g.rateSince = time.Now()
	g.mu.Unlock()
}

func (g *Guard) attributeResponse(files []string, since time.Time, detail map[string]any) (*suspectProc, func() error) {
	r := g.fileTrace.Lookup(files, since)
	detail["attribution"] = r
	deny := func() error { return fmt.Errorf("no verified writer identity") }
	if r.Status != "attributed" || r.Process == nil {
		return nil, deny
	}
	p, err := process.NewProcess(int32(r.Process.PID))
	if err != nil {
		r.Status = "unattributed"
		r.Reason = "writer_exited"
		detail["attribution"] = r
		return nil, deny
	}
	sp := takeForensics(p)
	if sp == nil || !strings.EqualFold(sp.Exe, r.Process.Image) {
		r.Status = "unattributed"
		r.Reason = "writer_identity_changed"
		detail["attribution"] = r
		return nil, deny
	}
	return sp, func() error { return filetrace.Terminate(*r.Process) }
}
