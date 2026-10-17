package resources

import (
	"context"
	"os"
	"time"

	"github.com/shirou/gopsutil/v4/process"
)

// ReadSelf uses native /proc counters on Linux and GetProcessTimes /
// GetProcessMemoryInfo on Windows through the existing gopsutil dependency.
func ReadSelf(ctx context.Context) (Sample, error) {
	s := Sample{At: time.Now()}
	p, err := process.NewProcessWithContext(ctx, int32(os.Getpid()))
	if err != nil {
		return s, err
	}
	t, err := p.TimesWithContext(ctx)
	if err != nil {
		return s, err
	}
	m, err := p.MemoryInfoWithContext(ctx)
	if err != nil {
		return s, err
	}
	s.CPUSeconds, s.RSSBytes = t.User+t.System, m.RSS
	return s, nil
}
