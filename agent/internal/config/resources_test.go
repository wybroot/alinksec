package config

import (
	"testing"
	"time"
)

func TestTrustedResourceConfiguration(t *testing.T) {
	c, err := Parse([]byte("resources:\n  cpu_percent: 4\n  cpu_window: 1m\n  recovery_window: 30s\n  rss_mib: 80\n  scan_rss_mib: 200\n  scan_mib_per_sec: 5\n"))
	if err != nil || c.Resources.CPUPercent != 4 || c.Resources.CPUWindow != time.Minute || c.Resources.RSSMiB != 80 {
		t.Fatalf("configuration: %+v %v", c, err)
	}
	for _, input := range []string{"cpu_percent: .nan", "cpu_percent: .inf", "cpu_window: 1s", "rss_mib: -1", "rss_mib: 999", "scan_mib_per_sec: 50", "enabled: false"} {
		if _, err := Parse([]byte("resources:\n  " + input + "\n")); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
}
