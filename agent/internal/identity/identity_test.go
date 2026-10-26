package identity

import (
	"math"
	"testing"
	"time"
)

func TestUnknownPercentIsNotMeasuredIdle(t *testing.T) {
	for _, value := range []float64{-1, 101, math.NaN(), math.Inf(1)} {
		if validPercent(value) {
			t.Fatalf("invalid measurement accepted: %v", value)
		}
	}
	if !validPercent(0) || !validPercent(100) {
		t.Fatal("valid measured endpoints rejected")
	}
}

func TestActualHostReportsHardwareAndBootIdentity(t *testing.T) {
	h := HostInfo()
	if h.Hostname == "" || h.Kernel == "" || h.CpuModel == "" || h.LogicalCpus == 0 || h.MemoryTotalBytes == 0 {
		t.Fatalf("incomplete actual host identity: %+v", h)
	}
	if h.BootTimeSec == 0 || h.BootTimeSec > uint64(time.Now().Unix()+300) {
		t.Fatal("invalid OS boot time")
	}
	sample := Sample()
	if sample.Host == nil || sample.UptimeSec <= 0 || !sample.MemValid {
		t.Fatal("actual host heartbeat is incomplete")
	}
}
