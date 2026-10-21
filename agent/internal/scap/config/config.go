package scapconfig

import (
	"errors"
	"path/filepath"
	"strings"
)

type Config struct {
	Enabled       bool   `yaml:"enabled"`
	RuntimeDir    string `yaml:"runtime_dir"`
	RuntimeSHA256 string `yaml:"runtime_sha256"`
	TimeoutSec    int    `yaml:"timeout_sec"`
}

func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if !filepath.IsAbs(c.RuntimeDir) || len(c.RuntimeDir) > 4096 || strings.ContainsRune(c.RuntimeDir, 0) || (len(c.RuntimeSHA256) != 64 || strings.Trim(c.RuntimeSHA256, "0123456789abcdef") != "") || c.TimeoutSec != 0 && (c.TimeoutSec < 30 || c.TimeoutSec > 1200) {
		return errors.New("SCAP requires an absolute runtime directory, a runtime manifest SHA256 and timeout 30..1200 seconds")
	}
	return nil
}
