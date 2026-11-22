package resources

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"
	"time"
)

type nativeObservation struct {
	Phase      string        `json:"phase"`
	Sample     Sample        `json:"sample"`
	State      State         `json:"state"`
	IntervalNS time.Duration `json:"interval_ns"`
	Error      string        `json:"error,omitempty"`
}

// Count the current low-load suffix from the raw counters, independently of
// the governor's reported percentage and recovery decision.
func nativeRecoverySpan(observations []nativeObservation, cfg Config) time.Duration {
	var span time.Duration
	for i := len(observations) - 1; i > 0; i-- {
		a, b := observations[i-1], observations[i]
		delta := b.Sample.At.Sub(a.Sample.At)
		if a.Error != "" || b.Error != "" || a.Sample.RSSBytes == 0 || b.Sample.RSSBytes == 0 ||
			delta <= 0 || delta > 3*SampleInterval ||
			math.IsNaN(a.Sample.CPUSeconds) || math.IsNaN(b.Sample.CPUSeconds) ||
			math.IsInf(a.Sample.CPUSeconds, 0) || math.IsInf(b.Sample.CPUSeconds, 0) ||
			a.Sample.CPUSeconds < 0 || b.Sample.CPUSeconds < a.Sample.CPUSeconds {
			break
		}
		percent := (b.Sample.CPUSeconds - a.Sample.CPUSeconds) / delta.Seconds() * 100
		if percent > cfg.CPUPercent*0.8 || b.Sample.RSSBytes >= (cfg.RSSMiB<<20)*8/10 {
			break
		}
		span += delta
	}
	return span
}

// This exercises actual counters and resident memory in the native test
// process. Protocol and service lifecycle evidence is recorded separately.
func TestNativeResourceFeedback(t *testing.T) {
	if os.Getenv("ALINKSEC_RESOURCE_NATIVE_REQUIRED") != "true" {
		t.Skip("native workload opt-in")
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Fatal("unsupported native target")
	}
	runNativeResourceFeedback(t, ReadSelf)
}

func runNativeResourceFeedback(t *testing.T, readSample func(context.Context) (Sample, error)) {
	t.Helper()
	path := os.Getenv("ALINKSEC_RESOURCE_EVIDENCE_FILE")
	if path == "" {
		t.Fatal("native evidence path required")
	}
	cfg := (Config{CPUWindow: 10 * time.Second, RecoveryWindow: 10 * time.Second, RSSMiB: 250, ScanRSSMiB: 250}).Defaults()
	started := time.Now()
	phase, failure := "setup", ""
	checks := []string{}
	samples := []State{}
	observations := []nativeObservation{}
	// Ordinary assertion/sampling failures must retain the evidence preceding
	// them. Do not write during sampling: evidence I/O would change CPU load.
	t.Cleanup(func() {
		result := map[string]any{
			"passed": !t.Failed(), "os": runtime.GOOS, "arch": runtime.GOARCH,
			"scope": "native_test_process_counters_and_workload", "checks": checks,
			"samples": samples, "observations": observations, "configuration": cfg,
			"phase": phase, "failure": failure, "started_at": started, "finished_at": time.Now(),
			"source": os.Getenv("GITHUB_SHA"), "run_id": os.Getenv("GITHUB_RUN_ID"),
			"run_attempt": os.Getenv("GITHUB_RUN_ATTEMPT"), "pid": os.Getpid(),
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Error(err)
			return
		}
		data, err := json.MarshalIndent(result, "", "  ")
		if err == nil {
			err = os.WriteFile(path, append(data, '\n'), 0600)
		}
		if err != nil {
			t.Error(err)
		}
	})
	fail := func(format string, args ...any) {
		t.Helper()
		failure = fmt.Sprintf(format, args...)
		t.Fatal(failure)
	}
	observe := func(g *Governor, stage string) Decision {
		t.Helper()
		phase = stage
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		s, err := readSample(ctx)
		decision := g.Observe(s, err)
		state := decision.State
		observation := nativeObservation{Phase: stage, Sample: s, State: state}
		if len(observations) > 0 {
			observation.IntervalNS = s.At.Sub(observations[len(observations)-1].Sample.At)
		}
		if err != nil {
			observation.Error = err.Error()
		}
		observations = append(observations, observation)
		samples = append(samples, state)
		if err != nil || s.RSSBytes == 0 {
			fail("native sample: %+v %v", s, err)
		}
		return decision
	}
	g := New(cfg)
	observe(g, "prime")
	checks = append(checks, "native_process_counters")
	buf := make([]byte, 64<<10)
	busy := func() {
		start := time.Now()
		for time.Since(start) < 150*time.Millisecond {
			sum := sha256.Sum256(buf)
			buf[0] = sum[0]
		}
	}
	for i := 0; i < 12 && g.State().Factor == 1; i++ {
		start := time.Now()
		busy()
		if delay := time.Until(start.Add(time.Second)); delay > 0 {
			time.Sleep(delay)
		}
		observe(g, "cpu_pressure")
	}
	if g.State().Factor != 2 || g.State().Reason != "cpu_pressure" {
		fail("actual sustained CPU feedback: %+v", g.State())
	}
	checks = append(checks, "actual_cpu_pressure")
	deadline := time.Now().Add(3 * cfg.RecoveryWindow)
	for i := 0; time.Now().Before(deadline); i++ {
		time.Sleep(time.Second)
		stage := "idle_recovery"
		if i == 3 {
			// Prove that an actual CPU interruption resets the low-load window.
			busy()
			stage = "recovery_interruption"
		}
		state := observe(g, stage).State
		if stage == "recovery_interruption" {
			if state.CPUPercent <= cfg.CPUPercent || state.Factor != 2 {
				fail("native CPU interruption not observed: %+v", state)
			}
			checks = append(checks, "actual_recovery_window_interruption")
		}
		span := nativeRecoverySpan(observations, cfg)
		if span < cfg.RecoveryWindow {
			if state.Factor != 2 || state.Reason != "cpu_pressure" {
				fail("recovered before a complete raw low-load window (%s): %+v", span, state)
			}
			continue
		}
		if state.Factor != 1 || state.Reason != "normal" {
			fail("complete raw low-load window (%s) did not recover: %+v", span, state)
		}
		break
	}
	if g.State().Factor != 1 {
		fail("native workload did not provide a complete low-load recovery window within %s: %+v", 3*cfg.RecoveryWindow, g.State())
	}
	checks = append(checks, "actual_idle_recovery")
	pressure := New(Config{RSSMiB: 64})
	resident := make([]byte, 72<<20)
	for i := 0; i < len(resident); i += 4096 {
		resident[i] = 1
	}
	d := observe(pressure, "resident_memory_pressure")
	runtime.KeepAlive(resident)
	if !d.Trim || d.State.Factor != 8 || d.State.RSSBytes < 64<<20 {
		fail("actual RSS feedback: %+v", d)
	}
	checks = append(checks, "actual_resident_memory_pressure")
	resident = nil
	debug.FreeOSMemory()
	if pressure.SoftMemoryLimit() != int64(64<<20)*7/10 {
		fail("soft cap")
	}
	checks = append(checks, "go_soft_limit_target")
	ioGovernor := New(Config{ScanMiBPerSec: 1})
	phase = "shared_io_pacing"
	start := time.Now()
	for i := 0; i < 4; i++ {
		if err := ioGovernor.WaitIO(context.Background(), 64<<10); err != nil {
			fail("shared IO: %v", err)
		}
	}
	if time.Since(start) < 240*time.Millisecond {
		fail("unpaced IO")
	}
	checks = append(checks, "actual_shared_io_pacing")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if ioGovernor.WaitIO(ctx, 64<<10) == nil {
		fail("uncancelable IO")
	}
	checks = append(checks, "actual_io_cancellation")
	phase = "sampling_failure"
	failedSample := Sample{At: time.Now()}
	failedState := pressure.Observe(failedSample, context.Canceled).State
	observations = append(observations, nativeObservation{Phase: phase, Sample: failedSample, State: failedState, Error: context.Canceled.Error()})
	samples = append(samples, failedState)
	if !failedState.SamplingOK {
		checks = append(checks, "sampling_failure_visible")
	} else {
		fail("sampling failure hidden")
	}
	phase = "complete"
}
