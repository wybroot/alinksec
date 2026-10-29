//go:build linux

package guard

import (
	"context"
	"fmt"
	"time"

	"github.com/alinksec/alinksec-agent/internal/filetrace"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func (g *Guard) configureAttribution()                 {} // No trusted Linux writer capture is installed.
func (g *Guard) runAttribution(context.Context) func() { return func() {} }
func (g *Guard) reportAttributionStatus() {
	g.mu.Lock()
	changed := g.traceStatus != "linux_writer_capture_unavailable"
	g.traceStatus = "linux_writer_capture_unavailable"
	g.mu.Unlock()
	if changed && g.report != nil {
		g.report(&pb.RptSecurityEvent{RuleId: "linux-ransom-attribution", RuleName: "Linux 勒索自动终止不可用", Type: "self_defense", Severity: pb.Severity_SEV_MEDIUM, ActionTaken: "alert_only", EventTs: time.Now().UnixMilli(), Detail: mustJSON(map[string]any{"attribution": filetrace.Result{Source: "none", Status: "unavailable", Reason: "linux_writer_capture_unavailable"}, "automatic_kill_supported": false})})
	}
}
func (g *Guard) attributeResponse(_ []string, _ time.Time, detail map[string]any) (*suspectProc, func() error) {
	// Neither an open descriptor (even writable) nor process start time proves
	// who changed a file. Until Linux has a trusted operation/instance capture,
	// keep detection and configured isolation, but never select a kill target.
	detail["attribution"] = filetrace.Result{
		Source: "none", Status: "unavailable", Reason: "linux_writer_capture_unavailable",
	}
	return nil, func() error { return fmt.Errorf("no verified Linux writer identity") }
}
