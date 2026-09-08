package guard

import (
	"os"
	"testing"

	"github.com/shirou/gopsutil/v3/process"
)

func TestTakeForensicsIncludesProcessLineage(t *testing.T) {
	p, err := process.NewProcess(int32(os.Getpid()))
	if err != nil {
		t.Skipf("current process unavailable: %v", err)
	}
	got := takeForensics(p)
	if got == nil || got.Pid != int32(os.Getpid()) {
		t.Fatalf("forensics = %#v, want current process", got)
	}
	if len(got.Lineage) == 0 || got.Lineage[0].Pid != got.Pid {
		t.Fatalf("lineage = %#v, want current process first", got.Lineage)
	}
	if len(got.Lineage) > 8 {
		t.Fatalf("lineage length = %d, want <= 8", len(got.Lineage))
	}
}
