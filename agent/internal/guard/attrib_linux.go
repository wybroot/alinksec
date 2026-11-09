//go:build linux

package guard

import (
	"context"
	"fmt"
	"time"
)

func (g *Guard) configureAttribution()                 {}
func (g *Guard) runAttribution(context.Context) func() { return func() {} }
func (g *Guard) reportAttributionStatus()              {}

// Open descriptors (even writable ones) and process creation times do not
// establish who changed a file. Until a trusted Linux file-operation source
// binds a write to a live process instance, never select a process to terminate.
func (g *Guard) attributeResponse(_ []string, _ time.Time, detail map[string]any) (*suspectProc, func() error) {
	detail["attribution"] = map[string]any{
		"source": "linux_writer_evidence",
		"status": "unavailable",
		"reason": "writer_evidence_unavailable",
	}
	return nil, func() error { return fmt.Errorf("no verified Linux writer identity") }
}
