//go:build windows

package logcollect

import (
	"os"
	"time"
)

func pollInterval() time.Duration { return 30 * time.Second }

// Security 4624/4625 XML is collected by windowslogin's single native reader.
func (c *Collector) pollOnce()              {}
func openLog(path string) (*os.File, error) { return os.Open(path) }
func fileIdentity(st os.FileInfo) string    { return st.Name() }
