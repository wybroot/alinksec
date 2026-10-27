//go:build linux

package guard

import (
	"context"
	"fmt"
	"time"

	"github.com/alinksec/alinksec-agent/internal/filetrace"
)

func (g *Guard) configureAttribution()                 {} // No trusted Linux writer capture is installed.
func (g *Guard) runAttribution(context.Context) func() { return func() {} }
func (g *Guard) reportAttributionStatus()              {}
func (g *Guard) attributeResponse(_ []string, _ time.Time, detail map[string]any) (*suspectProc, func() error) {
	// Neither an open descriptor (even writable) nor process start time proves
	// who changed a file. Until Linux has a trusted operation/instance capture,
	// keep detection and configured isolation, but never select a kill target.
	detail["attribution"] = filetrace.Result{
		Source: "none", Status: "unavailable", Reason: "linux_writer_capture_unavailable",
	}
	return nil, func() error { return fmt.Errorf("no verified Linux writer identity") }
}
