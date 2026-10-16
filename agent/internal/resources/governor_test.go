package resources

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"
)

func TestSustainedCPUAndHysteresis(t *testing.T) {
	g := New(Config{})
	at := time.Now()
	cpu := 0.0
	step := func(seconds int, percent float64) Decision {
		at = at.Add(time.Duration(seconds) * time.Second)
		cpu += float64(seconds) * percent / 100
		return g.Observe(Sample{at, cpu, 30 << 20}, nil)
	}
	step(0, 0)
	for i := 0; i < 29; i++ {
		if s := step(10, 4).State; s.Factor != 1 {
			t.Fatalf("early throttle: %+v", s)
		}
	}
	if s := step(10, 4).State; s.Factor != 2 || s.Reason != "cpu_pressure" {
		t.Fatalf("no throttle: %+v", s)
	}
	for i := 0; i < 30; i++ {
		step(10, 4)
	}
	if g.State().Factor != 4 {
		t.Fatal("sustained CPU did not escalate")
	}
	for i := 0; i < 11; i++ {
		step(10, 1)
	}
	if g.State().Factor != 4 {
		t.Fatal("early recovery")
	}
	if step(10, 1).State.Factor != 2 {
		t.Fatal("no gradual recovery")
	}
	for i := 0; i < 12; i++ {
		step(10, 1)
	}
	if g.State().Factor != 1 || g.State().Reason != "normal" {
		t.Fatal("not recovered")
	}
}

func TestMemoryTrimScanThresholdAndFailure(t *testing.T) {
	g := New(Config{})
	at := time.Now()
	observe := func(rss uint64, err error) Decision {
		at = at.Add(10 * time.Second)
		return g.Observe(Sample{at, 1, rss << 20}, err)
	}
	done := g.BeginScan()
	if d := observe(120, nil); d.Trim || d.State.Factor != 1 {
		t.Fatal("scan RSS allowance ignored")
	}
	done()
	done()
	if d := observe(120, nil); !d.Trim || d.State.Factor != 8 || d.State.ScanActive {
		t.Fatalf("missing idle pressure: %+v", d)
	}
	if observe(120, nil).Trim {
		t.Fatal("unbounded GC frequency")
	}
	for i := 0; i < 4; i++ {
		observe(120, nil)
	}
	if !observe(120, nil).Trim {
		t.Fatal("no periodic reclamation")
	}
	if d := observe(0, errors.New("native sampling failed")); d.State.SamplingOK || d.State.Reason != "sampling_unavailable" {
		t.Fatal("failure looked healthy")
	}
	if d := observe(30, nil); d.State.Factor != 8 || d.State.CPUReady {
		t.Fatal("unprimed recovery")
	}
}

func TestCounterDiscontinuitiesBreakWindows(t *testing.T) {
	for _, discontinuity := range []string{"gap", "reset", "error", "nan"} {
		t.Run(discontinuity, func(t *testing.T) {
			g := New(Config{CPUWindow: 20 * time.Second, RecoveryWindow: 20 * time.Second})
			at := time.Now()
			g.Observe(Sample{at, 1, 30 << 20}, nil)
			g.Observe(Sample{at.Add(10 * time.Second), 2, 30 << 20}, nil)
			s := Sample{at.Add(20 * time.Second), 3, 30 << 20}
			var err error
			switch discontinuity {
			case "gap":
				s.At = at.Add(time.Minute)
			case "reset":
				s.CPUSeconds = 0
			case "error":
				err = errors.New("failure")
			case "nan":
				s.CPUSeconds = math.NaN()
			}
			g.Observe(s, err)
			want := 1
			if discontinuity == "error" || discontinuity == "nan" {
				want = 2
			}
			if st := g.Observe(Sample{s.At.Add(10 * time.Second), s.CPUSeconds + 1, 30 << 20}, nil).State; st.Factor != want {
				t.Fatal("discontinuous samples accumulated")
			}
		})
	}
}

func TestPacingSharedAcrossFilesAndEnginesAndCancelable(t *testing.T) {
	g := New(Config{ScanMiBPerSec: 1})
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := g.WaitIO(context.Background(), 32<<10); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if time.Since(start) < 120*time.Millisecond {
		t.Fatal("parallel engines exceeded shared rate")
	}
	g.Observe(Sample{time.Now(), 1, 101 << 20}, nil)
	start = time.Now()
	if err := g.WaitIO(context.Background(), 32<<10); err != nil || time.Since(start) < 240*time.Millisecond {
		t.Fatal("pressure did not reduce rate")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := g.WaitIO(ctx, 64<<10); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
	g.ioLane <- struct{}{}
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := g.WaitIO(ctx, 64<<10); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("queued cancellation ignored")
	}
	<-g.ioLane
}

func TestResourceConfigurationBounds(t *testing.T) {
	for _, cfg := range []Config{{CPUPercent: math.NaN()}, {CPUPercent: math.Inf(1)}, {CPUPercent: 26}, {CPUWindow: time.Second}, {RecoveryWindow: -1}, {RSSMiB: 31}, {RSSMiB: 251}, {ScanRSSMiB: 99}, {ScanRSSMiB: 501}, {ScanMiBPerSec: 11}} {
		if cfg.Validate() == nil {
			t.Fatalf("accepted %+v", cfg)
		}
	}
	if (Config{}).Validate() != nil {
		t.Fatal("invalid defaults")
	}
	g := New(Config{})
	g.Observe(Sample{time.Now(), 1, 101 << 20}, nil)
	if got := g.Interval(time.Duration(math.MaxInt64)); got != time.Duration(math.MaxInt64) {
		t.Fatal("interval overflow")
	}
}
