//go:build windows

package logcollect

import "time"

func pollInterval()time.Duration{return 30*time.Second}

// Security logons are read by windowslogin's native XML reader and committed
// with its cursor. Do not run a second overlapping reader or localized CLI parser.
func (c *Collector) pollOnce(){}
