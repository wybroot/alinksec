package resources

import (
	"context"
	"math"
	"sync"
	"time"
)

type Sample struct {
	At         time.Time
	CPUSeconds float64
	RSSBytes   uint64
}

type State struct {
	At         time.Time `json:"at"`
	CPUPercent float64   `json:"cpu_percent_single_core"`
	RSSBytes   uint64    `json:"rss_bytes"`
	Factor     int       `json:"factor"`
	Reason     string    `json:"reason"`
	SamplingOK bool      `json:"sampling_ok"`
	CPUReady   bool      `json:"cpu_ready"`
	ScanActive bool      `json:"scan_active"`
}

type Decision struct {
	State   State
	Changed bool
	Trim    bool
}

type Governor struct {
	mu                            sync.Mutex
	cfg                           Config
	state                         State
	previous                      Sample
	highSince, lowSince, lastTrim time.Time
	scans                         int
	ioLane                        chan struct{}
}

func New(cfg Config) *Governor {
	return &Governor{cfg: cfg.Defaults(), state: State{Factor: 1, Reason: "normal"}, ioLane: make(chan struct{}, 1)}
}

func (g *Governor) State() State {
	if g == nil {
		return State{Factor: 1, Reason: "normal"}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.state
}

// BeginScan changes only the RSS feedback threshold. It never raises the Go
// memory limit, stops the sampler, or exempts the scan from CPU feedback.
func (g *Governor) BeginScan() func() {
	if g == nil {
		return func() {}
	}
	g.mu.Lock()
	g.scans++
	g.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { g.mu.Lock(); g.scans--; g.mu.Unlock() }) }
}

// Observe requires cumulative process CPU time. Percent is relative to ONE
// logical CPU (100% = one busy core), independent of host core count.
// Missing, stale or reset counters break sustained windows and cannot recover.
func (g *Governor) Observe(s Sample, err error) Decision {
	g.mu.Lock()
	defer g.mu.Unlock()
	old := g.state
	now := s.At
	if now.IsZero() {
		now = time.Now()
	}
	g.state.At, g.state.ScanActive = now, g.scans > 0
	valid := err == nil && s.RSSBytes > 0 && !math.IsNaN(s.CPUSeconds) && !math.IsInf(s.CPUSeconds, 0) && s.CPUSeconds >= 0
	delta := now.Sub(g.previous.At)
	contiguous := valid && !g.previous.At.IsZero() && delta > 0 && delta <= 3*SampleInterval && s.CPUSeconds >= g.previous.CPUSeconds
	g.state.SamplingOK = valid
	g.state.CPUReady = contiguous
	trim := false
	if !valid {
		g.previous = Sample{}
		g.highSince, g.lowSince = time.Time{}, time.Time{}
		g.state.Factor = max(2, g.state.Factor)
		g.state.Reason = "sampling_unavailable"
	} else {
		g.state.RSSBytes = s.RSSBytes
		g.state.CPUPercent = 0
		if contiguous {
			g.state.CPUPercent = (s.CPUSeconds - g.previous.CPUSeconds) / delta.Seconds() * 100
		}
		limit := g.cfg.RSSMiB << 20
		if g.scans > 0 {
			limit = g.cfg.ScanRSSMiB << 20
		}
		if s.RSSBytes >= limit {
			g.state.Factor, g.state.Reason = 8, "rss_pressure"
			g.highSince, g.lowSince = time.Time{}, time.Time{}
			if g.lastTrim.IsZero() || now.Sub(g.lastTrim) >= time.Minute {
				trim = true
				g.lastTrim = now
			}
		} else if !contiguous {
			g.highSince, g.lowSince = time.Time{}, time.Time{}
		} else if g.state.CPUPercent > g.cfg.CPUPercent {
			g.lowSince = time.Time{}
			if g.highSince.IsZero() {
				g.highSince = g.previous.At
			}
			if now.Sub(g.highSince) >= g.cfg.CPUWindow {
				g.state.Factor = min(8, g.state.Factor*2)
				g.state.Reason = "cpu_pressure"
				g.highSince = now
			}
		} else {
			g.highSince = time.Time{}
			if g.state.CPUPercent <= g.cfg.CPUPercent*0.8 && s.RSSBytes < limit*8/10 {
				if g.lowSince.IsZero() {
					g.lowSince = g.previous.At
				}
				if now.Sub(g.lowSince) >= g.cfg.RecoveryWindow {
					g.state.Factor = max(1, g.state.Factor/2)
					g.state.Reason = "recovering"
					if g.state.Factor == 1 {
						g.state.Reason = "normal"
					}
					g.lowSince = now
				}
			} else {
				g.lowSince = time.Time{}
			}
		}
		g.previous = s
	}
	return Decision{State: g.state, Changed: old.Factor != g.state.Factor || old.Reason != g.state.Reason || old.SamplingOK != g.state.SamplingOK, Trim: trim}
}

func (g *Governor) Interval(base time.Duration) time.Duration {
	factor := g.State().Factor
	if base > time.Duration(math.MaxInt64)/time.Duration(factor) {
		return time.Duration(math.MaxInt64)
	}
	return base * time.Duration(factor)
}

// WaitIO shares a single paced lane across engines. No burst credit accumulates
// between files and cancellation never reserves future capacity. Each chunk is
// bounded to 64KiB by the caller; metadata work also consumes a small allowance.
func (g *Governor) WaitIO(ctx context.Context, bytes int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if g == nil {
		return nil
	}
	select {
	case g.ioLane <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-g.ioLane }()
	if err := ctx.Err(); err != nil {
		return err
	}
	delay := time.Duration(max(0, bytes)) * time.Second * time.Duration(g.State().Factor) / time.Duration(g.cfg.ScanMiBPerSec<<20)
	if delay <= 0 {
		return nil
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// SoftMemoryLimit leaves room for stacks, mappings and native allocations. It is
// a Go runtime target, not an RSS ceiling; callers preserve a tighter prior cap.
func (g *Governor) SoftMemoryLimit() int64 { return int64(g.cfg.RSSMiB<<20) * 7 / 10 }
