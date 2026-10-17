package resources

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"
	"time"
)

// This exercises actual counters and resident memory in the native test
// process. Protocol and service lifecycle evidence is recorded separately.
func TestNativeResourceFeedback(t *testing.T) {
	if os.Getenv("ALINKSEC_RESOURCE_NATIVE_REQUIRED") != "true" {
		t.Skip("native workload opt-in")
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Fatal("unsupported native target")
	}
	read := func() Sample {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		s, err := ReadSelf(ctx)
		if err != nil || s.RSSBytes == 0 {
			t.Fatalf("native sample: %+v %v", s, err)
		}
		return s
	}
	checks := []string{"native_process_counters"}
	samples := []State{}
	g := New(Config{CPUWindow: 10 * time.Second, RecoveryWindow: 10 * time.Second, RSSMiB: 250, ScanRSSMiB: 250})
	g.Observe(read(), nil)
	buf := make([]byte, 64<<10)
	for i := 0; i < 12 && g.State().Factor == 1; i++ {
		start := time.Now()
		for time.Since(start) < 150*time.Millisecond {
			sum := sha256.Sum256(buf)
			buf[0] = sum[0]
		}
		if delay := time.Until(start.Add(time.Second)); delay > 0 {
			time.Sleep(delay)
		}
		samples = append(samples, g.Observe(read(), nil).State)
	}
	if g.State().Factor != 2 || g.State().Reason != "cpu_pressure" {
		t.Fatalf("actual sustained CPU feedback: %+v", g.State())
	}
	checks = append(checks, "actual_cpu_pressure")
	for i := 0; i < 14 && g.State().Factor > 1; i++ {
		time.Sleep(time.Second)
		samples = append(samples, g.Observe(read(), nil).State)
	}
	if g.State().Factor != 1 {
		t.Fatalf("idle recovery: %+v", g.State())
	}
	checks = append(checks, "actual_idle_recovery")
	pressure := New(Config{RSSMiB: 64})
	resident := make([]byte, 72<<20)
	for i := 0; i < len(resident); i += 4096 {
		resident[i] = 1
	}
	d := pressure.Observe(read(), nil)
	runtime.KeepAlive(resident)
	if !d.Trim || d.State.Factor != 8 || d.State.RSSBytes < 64<<20 {
		t.Fatalf("actual RSS feedback: %+v", d)
	}
	samples = append(samples, d.State)
	checks = append(checks, "actual_resident_memory_pressure")
	resident = nil
	debug.FreeOSMemory()
	if pressure.SoftMemoryLimit() != int64(64<<20)*7/10 {
		t.Fatal("soft cap")
	}
	checks = append(checks, "go_soft_limit_target")
	ioGovernor := New(Config{ScanMiBPerSec: 1})
	start := time.Now()
	for i := 0; i < 4; i++ {
		if err := ioGovernor.WaitIO(context.Background(), 64<<10); err != nil {
			t.Fatal(err)
		}
	}
	if time.Since(start) < 240*time.Millisecond {
		t.Fatal("unpaced IO")
	}
	checks = append(checks, "actual_shared_io_pacing")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if ioGovernor.WaitIO(ctx, 64<<10) == nil {
		t.Fatal("uncancelable IO")
	}
	checks = append(checks, "actual_io_cancellation")
	if !pressure.Observe(Sample{At: time.Now()}, context.Canceled).State.SamplingOK {
		checks = append(checks, "sampling_failure_visible")
	} else {
		t.Fatal("sampling failure hidden")
	}
	result := map[string]any{"passed": true, "os": runtime.GOOS, "arch": runtime.GOARCH, "scope": "native_test_process_counters_and_workload", "checks": checks, "samples": samples}
	path := os.Getenv("ALINKSEC_RESOURCE_EVIDENCE_FILE")
	if path == "" {
		t.Fatal("native evidence path required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}
