package comm

import (
	"context"
	"encoding/json"
	"runtime/debug"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/resources"
	"github.com/alinksec/alinksec-agent/internal/virusscan"
)

func (c *Client) resourceLoop(ctx context.Context) {
	previous := debug.SetMemoryLimit(-1)
	if limit := c.resources.SoftMemoryLimit(); limit < previous {
		debug.SetMemoryLimit(limit)
		defer debug.SetMemoryLimit(previous)
	}
	c.monitorResources(ctx, resources.SampleInterval, resources.ReadSelf, debug.FreeOSMemory)
}

func (c *Client) monitorResources(ctx context.Context, interval time.Duration, read func(context.Context) (resources.Sample, error), trim func()) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		sctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		sample, err := read(sctx)
		cancel()
		d := c.resources.Observe(sample, err)
		if d.Trim {
			// Only evict recreatable caches. Do not remove policies, command
			// deduplication, offline security reports or protection baselines.
			virusscan.TrimReadBuffers()
			trim()
		}
		if d.Changed {
			data, _ := json.Marshal(d.State)
			c.log.Info("Agent resource feedback", "factor", d.State.Factor, "reason", d.State.Reason, "rss", d.State.RSSBytes)
			c.reportSecurityEvent(&pb.RptSecurityEvent{Type: "self_defense", RuleId: "agent-resources", RuleName: "Agent 资源自适应", Severity: pb.Severity_SEV_INFO, Detail: string(data), ActionTaken: "background_adjusted", EventTs: d.State.At.UnixMilli()})
		}
		c.pushMetrics(resourceMetrics(d.State))
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func resourceMetrics(s resources.State) []*pb.MetricSample {
	values := map[string]float64{
		"alinksec_agent_resource_factor":      float64(s.Factor),
		"alinksec_agent_resource_sampling_ok": 0,
	}
	if s.SamplingOK {
		values["alinksec_agent_resource_sampling_ok"] = 1
		values["alinksec_agent_rss_bytes"] = float64(s.RSSBytes)
		if s.CPUReady {
			values["alinksec_agent_cpu_percent_single_core"] = s.CPUPercent
		}
	}
	out := make([]*pb.MetricSample, 0, len(values))
	for name, value := range values {
		out = append(out, &pb.MetricSample{Name: name, Value: value, Ts: s.At.UnixMilli()})
	}
	return out
}

// All optional bulk work shares one slot. Never hold it while waiting for a
// command acknowledgement, heartbeat, isolation lease or local guard response.
func (c *Client) beginBulk() bool { return c.bulkBusy.CompareAndSwap(false, true) }

func (c *Client) resourceBusy(received *pb.RptAck) []*pb.RptAck {
	return []*pb.RptAck{received, {CmdId: received.GetCmdId(), Stage: pb.RptAck_FAILED, Code: 2, Message: "后台采集或扫描正在执行，请稍后重试"}}
}
