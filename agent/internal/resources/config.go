// Package resources controls optional background work without stopping management
// traffic or security response. Thresholds are feedback targets, not OS quotas.
package resources

import (
	"fmt"
	"math"
	"time"
)

const SampleInterval = 10 * time.Second

type Config struct {
	CPUPercent     float64       `yaml:"cpu_percent" json:"cpu_percent"`
	CPUWindow      time.Duration `yaml:"cpu_window" json:"cpu_window"`
	RecoveryWindow time.Duration `yaml:"recovery_window" json:"recovery_window"`
	RSSMiB         uint64        `yaml:"rss_mib" json:"rss_mib"`
	ScanRSSMiB     uint64        `yaml:"scan_rss_mib" json:"scan_rss_mib"`
	ScanMiBPerSec  uint64        `yaml:"scan_mib_per_sec" json:"scan_mib_per_sec"`
}

func (c Config) Defaults() Config {
	if c.CPUPercent == 0 {
		c.CPUPercent = 3
	}
	if c.CPUWindow == 0 {
		c.CPUWindow = 5 * time.Minute
	}
	if c.RecoveryWindow == 0 {
		c.RecoveryWindow = 2 * time.Minute
	}
	if c.RSSMiB == 0 {
		c.RSSMiB = 100
	}
	if c.ScanRSSMiB == 0 {
		c.ScanRSSMiB = 250
	}
	if c.ScanMiBPerSec == 0 {
		c.ScanMiBPerSec = 10
	}
	return c
}

func (c Config) Validate() error {
	c = c.Defaults()
	if math.IsNaN(c.CPUPercent) || math.IsInf(c.CPUPercent, 0) || c.CPUPercent < 1 || c.CPUPercent > 25 ||
		c.CPUWindow < SampleInterval || c.CPUWindow > 30*time.Minute ||
		c.RecoveryWindow < SampleInterval || c.RecoveryWindow > 30*time.Minute ||
		c.RSSMiB < 32 || c.RSSMiB > 250 || c.ScanRSSMiB < c.RSSMiB || c.ScanRSSMiB > 500 ||
		c.ScanMiBPerSec < 1 || c.ScanMiBPerSec > 10 {
		return fmt.Errorf("resources 参数超出范围")
	}
	return nil
}
