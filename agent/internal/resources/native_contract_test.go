package resources

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativeRecoverySpanUsesRawCounters(t *testing.T) {
	cfg := (Config{}).Defaults()
	for _, test := range []struct {
		name   string
		change func([]nativeObservation)
		want   time.Duration
	}{
		{"uninterrupted", func(_ []nativeObservation) {}, 14 * time.Second},
		{"late_cpu_spike", func(s []nativeObservation) {
			for i := 5; i < len(s); i++ {
				s[i].Sample.CPUSeconds += 0.04
			}
		}, 9 * time.Second},
		{"high_rss", func(s []nativeObservation) { s[5].Sample.RSSBytes = 81 << 20 }, 9 * time.Second},
		{"sampling_error", func(s []nativeObservation) { s[5].Error = "unavailable" }, 8 * time.Second},
		{"reset", func(s []nativeObservation) {
			for i := 5; i < len(s); i++ {
				s[i].Sample.CPUSeconds = 0
			}
		}, 9 * time.Second},
		{"missing_rss", func(s []nativeObservation) { s[5].Sample.RSSBytes = 0 }, 8 * time.Second},
		{"nan_counter", func(s []nativeObservation) { s[5].Sample.CPUSeconds = math.NaN() }, 8 * time.Second},
		{"infinite_counter", func(s []nativeObservation) { s[5].Sample.CPUSeconds = math.Inf(1) }, 8 * time.Second},
		{"gap", func(s []nativeObservation) {
			for i := 5; i < len(s); i++ {
				s[i].Sample.At = s[i].Sample.At.Add(31 * time.Second)
			}
		}, 9 * time.Second},
		{"repeated_timestamp", func(s []nativeObservation) { s[5].Sample.At = s[4].Sample.At }, 10 * time.Second},
		{"reported_state_cannot_supply_raw_window", func(s []nativeObservation) {
			for i := range s {
				s[i].State = State{CPUPercent: 0, CPUReady: true, SamplingOK: true, Factor: 1}
				s[i].Sample.CPUSeconds = float64(i)
			}
		}, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			samples := make([]nativeObservation, 15)
			for i := range samples {
				samples[i].Sample = Sample{time.Unix(100+int64(i), 0), 1, 30 << 20}
			}
			test.change(samples)
			if got := nativeRecoverySpan(samples, cfg); got != test.want {
				t.Fatalf("raw recovery span %s, want %s", got, test.want)
			}
		})
	}
}

func TestNativeSamplingFailureRetainsEvidence(t *testing.T) {
	const childFlag = "ALINKSEC_NATIVE_RESOURCE_FAILURE_CHILD"
	if os.Getenv(childFlag) == "1" {
		runNativeResourceFeedback(t, func(context.Context) (Sample, error) {
			return Sample{At: time.Unix(100, 0)}, errors.New("controlled native counter failure")
		})
		return
	}
	path := filepath.Join(t.TempDir(), "failure.json")
	cmd := exec.Command(os.Args[0], "-test.run=^TestNativeSamplingFailureRetainsEvidence$", "-test.count=1")
	cmd.Env = append(os.Environ(), childFlag+"=1", "ALINKSEC_RESOURCE_EVIDENCE_FILE="+path)
	output, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("controlled child failure: %v\n%s", err, output)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failure evidence missing: %v\n%s", err, output)
	}
	var result struct {
		Passed       bool                `json:"passed"`
		Phase        string              `json:"phase"`
		Failure      string              `json:"failure"`
		Observations []nativeObservation `json:"observations"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Passed || result.Phase != "prime" || !strings.Contains(result.Failure, "controlled native counter failure") ||
		len(result.Observations) != 1 || result.Observations[0].Error != "controlled native counter failure" ||
		result.Observations[0].State.SamplingOK || result.Observations[0].State.Reason != "sampling_unavailable" {
		t.Fatalf("sampling failure was not retained accurately: %s", data)
	}
}
