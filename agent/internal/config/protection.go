package config

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"time"
	_ "time/tzdata"
)

const MaxProtectedFileBytes int64 = 1 << 20

type FileRule struct {
	ID       string    `yaml:"id" json:"id"`
	Name     string    `yaml:"name" json:"name"`
	Enabled  bool      `yaml:"enabled" json:"enabled"`
	Severity int       `yaml:"severity" json:"severity"`
	Match    FileMatch `yaml:"match" json:"match"`
	Actions  []string  `yaml:"actions" json:"actions"`
}

type FileMatch struct {
	Platforms    []string `yaml:"platforms" json:"platforms"`
	Paths        []string `yaml:"paths" json:"paths"`
	MaxFileBytes int64    `yaml:"max_file_bytes" json:"max_file_bytes"`
}

type LoginRule struct {
	ID       string     `yaml:"id" json:"id"`
	Name     string     `yaml:"name" json:"name"`
	Enabled  bool       `yaml:"enabled" json:"enabled"`
	Severity int        `yaml:"severity" json:"severity"`
	Match    LoginMatch `yaml:"match" json:"match"`
	Actions  []string   `yaml:"actions" json:"actions"`
}

type LoginMatch struct {
	Platforms        []string `yaml:"platforms" json:"platforms"`
	WindowSec        int      `yaml:"window_sec" json:"window_sec"`
	FailureThreshold int      `yaml:"failure_threshold" json:"failure_threshold"`
	CooldownSec      int      `yaml:"cooldown_sec" json:"cooldown_sec"`
	BlockDurationSec int      `yaml:"block_duration_sec" json:"block_duration_sec"`
	SSHPorts         []int    `yaml:"ssh_ports" json:"ssh_ports"`
	TrustedIPs       []string `yaml:"trusted_ips" json:"trusted_ips"`
	UserExclude      []string `yaml:"user_exclude" json:"user_exclude"`
	OffHoursEnabled  bool     `yaml:"off_hours_enabled" json:"off_hours_enabled"`
	AllowedStartHour int      `yaml:"allowed_start_hour" json:"allowed_start_hour"`
	AllowedEndHour   int      `yaml:"allowed_end_hour" json:"allowed_end_hour"`
	Timezone         string   `yaml:"timezone" json:"timezone"`
}

func (m FileMatch) Limit() int64 {
	if m.MaxFileBytes == 0 {
		return MaxProtectedFileBytes
	}
	return m.MaxFileBytes
}

func (m LoginMatch) Defaults() LoginMatch {
	if m.WindowSec == 0 {
		m.WindowSec = 300
	}
	if m.FailureThreshold == 0 {
		m.FailureThreshold = 5
	}
	if m.CooldownSec == 0 {
		m.CooldownSec = 300
	}
	if m.BlockDurationSec == 0 {
		m.BlockDurationSec = 600
	}
	if len(m.SSHPorts) == 0 {
		m.SSHPorts = []int{22}
	}
	if m.Timezone == "" {
		m.Timezone = "Local"
	}
	return m
}

func ValidateProtection(files []FileRule, logins []LoginRule) error {
	paths := 0
	if len(files) > 64 || len(logins) > 16 {
		return fmt.Errorf("防护规则数量超过上限")
	}
	for _, rule := range files {
		paths += len(rule.Match.Paths)
		if !validRuleID(rule.ID) || len(rule.Match.Paths) == 0 || paths > 64 || rule.Match.Limit() < 1 || rule.Match.Limit() > MaxProtectedFileBytes {
			return fmt.Errorf("文件规则 %s 的路径数量或大小上限无效", rule.ID)
		}
		for _, path := range rule.Match.Paths {
			windowsAbsolute := len(path) > 2 && path[1] == ':' && (path[2] == '\\' || path[2] == '/')
			if len(path) > 4096 || strings.ContainsRune(path, 0) || (!filepath.IsAbs(path) && !windowsAbsolute && !strings.HasPrefix(path, "/")) {
				return fmt.Errorf("文件规则 %s 需要绝对路径", rule.ID)
			}
		}
		if err := validateActions(rule.Actions, "restore"); err != nil {
			return err
		}
		if err := validatePlatforms(rule.Match.Platforms); err != nil {
			return err
		}
	}
	for _, rule := range logins {
		m := rule.Match.Defaults()
		if !validRuleID(rule.ID) || m.WindowSec < 1 || m.WindowSec > 3600 || m.FailureThreshold < 2 || m.FailureThreshold > 100 || m.CooldownSec < 1 || m.CooldownSec > 86400 || m.BlockDurationSec < 5 || m.BlockDurationSec > 3600 || len(m.SSHPorts) > 16 || len(m.TrustedIPs) > 128 || len(m.UserExclude) > 64 {
			return fmt.Errorf("登录规则 %s 的阈值、窗口或封禁参数无效", rule.ID)
		}
		if m.AllowedStartHour < 0 || m.AllowedStartHour > 23 || m.AllowedEndHour < 0 || m.AllowedEndHour > 24 {
			return fmt.Errorf("登录规则 %s 的登录时段无效", rule.ID)
		}
		if _, err := time.LoadLocation(m.Timezone); err != nil {
			return fmt.Errorf("登录规则 %s 的时区无效", rule.ID)
		}
		for _, port := range m.SSHPorts {
			if port < 1 || port > 65535 {
				return fmt.Errorf("SSH 端口无效")
			}
		}
		for _, value := range m.TrustedIPs {
			if _, err := netip.ParseAddr(value); err != nil {
				if _, err := netip.ParsePrefix(value); err != nil {
					return fmt.Errorf("信任 IP 或网段无效: %s", value)
				}
			}
		}
		for _, user := range m.UserExclude {
			if user == "" || len(user) > 128 || strings.ContainsRune(user, 0) {
				return fmt.Errorf("排除账户无效")
			}
		}
		if err := validateActions(rule.Actions, "block_ip"); err != nil {
			return err
		}
		if err := validatePlatforms(m.Platforms); err != nil {
			return err
		}
	}
	return nil
}

func validateActions(actions []string, response string) error {
	if len(actions) > 2 {
		return fmt.Errorf("防护动作数量超过上限")
	}
	for _, action := range actions {
		if action != "alert" && action != response {
			return fmt.Errorf("不支持的防护响应: %s", action)
		}
	}
	return nil
}

func validatePlatforms(platforms []string) error {
	if len(platforms) > 2 {
		return fmt.Errorf("防护平台数量超过上限")
	}
	for _, platform := range platforms {
		if platform != "linux" && platform != "windows" {
			return fmt.Errorf("不支持的防护平台: %s", platform)
		}
	}
	return nil
}

func validRuleID(id string) bool {
	return id != "" && len(id) <= 128 && !strings.ContainsRune(id, 0)
}
