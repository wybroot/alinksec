package comm

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/alinksec/alinksec-agent/internal/baseline"
	"github.com/alinksec/alinksec-agent/internal/virusscan"
)

func (c *Client) channelObservation() baseline.ChannelObservation {
	c.reportMu.Lock()
	defer c.reportMu.Unlock()
	return baseline.ChannelObservation{Session: c.channelSession, Active: c.channelActive, LastSend: c.channelSend, LastReceive: c.channelReceive}
}
func (c *Client) channelObservationContext(ctx context.Context) (baseline.ChannelObservation, error) {
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !c.reportMu.TryLock() {
		select {
		case <-ctx.Done():
			return baseline.ChannelObservation{}, ctx.Err()
		case <-tick.C:
		}
	}
	defer c.reportMu.Unlock()
	if ctx.Err() != nil {
		return baseline.ChannelObservation{}, ctx.Err()
	}
	return baseline.ChannelObservation{Session: c.channelSession, Active: c.channelActive, LastSend: c.channelSend, LastReceive: c.channelReceive}, nil
}
func (c *Client) noteChannelActivity(session uint64, sending bool) {
	c.reportMu.Lock()
	defer c.reportMu.Unlock()
	if !c.channelActive || session != c.channelSession {
		return
	}
	if sending {
		c.channelSend = time.Now()
	} else {
		c.channelReceive = time.Now()
	}
}
func (c *Client) baselineRuntime() *baseline.AgentRuntime {
	workDir, err := filepath.Abs(c.workDir)
	if err != nil {
		return nil
	}
	return &baseline.AgentRuntime{WorkDir: workDir, Channel: c.channelObservationContext, Signature: func(ctx context.Context) (baseline.SignatureObservation, error) {
		if ctx.Err() != nil {
			return baseline.SignatureObservation{}, ctx.Err()
		}
		version, count, rules, hashes, generation, ok := virusscan.CachedHashSnapshot(ctx, c.workDir, 1024)
		if !ok {
			return baseline.SignatureObservation{}, fmt.Errorf("current cache unavailable or outside bound")
		}
		out := baseline.SignatureObservation{Version: version, HashCount: count, RuleCount: rules, Generation: generation, Hashes: map[string]baseline.SignatureEntry{}}
		for hash, entry := range hashes {
			out.Hashes[hash] = baseline.SignatureEntry{Name: entry.Name, Severity: entry.Severity}
		}
		return out, ctx.Err()
	}}
}
