package guard

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/alinksec/alinksec-agent/internal/config"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

var sshAttemptPattern = regexp.MustCompile(`\bsshd(?:\[\d+\])?:\s+(Failed|Accepted)\s+([A-Za-z0-9_/-]+)\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+\d+`)
var syslogTimePattern = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s`)

type loginAttempt struct {
	IP     netip.Addr
	User   string
	Method string
	Failed bool
	Time   time.Time
}

type loginBucket struct {
	Failures  []int64 `json:"failures"`
	LastAlert int64   `json:"last_alert"`
	LastSeen  int64   `json:"last_seen"`
}

type loginBlock struct {
	RuleID  string `json:"rule_id"`
	IP      string `json:"ip"`
	Ports   []int  `json:"ports"`
	Expires int64  `json:"expires"`
}

type loginState struct {
	Buckets map[string]*loginBucket `json:"buckets"`
	Blocks  map[string]loginBlock   `json:"blocks"`
}

type loginMonitor struct {
	mu         sync.Mutex
	path       string
	log        *slog.Logger
	rules      map[string]config.LoginRule
	state      loginState
	applied    map[string]bool
	apply      func(loginBlock, bool) error
	now        func() time.Time
	reset      func() error
	needsReset bool
}

func newLoginMonitor(workDir string, log *slog.Logger, apply func(loginBlock, bool) error) *loginMonitor {
	m := &loginMonitor{path: filepath.Join(workDir, "login-protection.json"), log: log,
		rules: map[string]config.LoginRule{}, state: loginState{Buckets: map[string]*loginBucket{}, Blocks: map[string]loginBlock{}},
		applied: map[string]bool{}, apply: apply, now: time.Now, reset: func() error { return nil }}
	if _, err := os.Stat(m.path); err == nil {
		m.needsReset = true
		if data, err := readPrivateLimited(m.path, 4<<20); err == nil {
			var state loginState
			if json.Unmarshal(data, &state) == nil && validLoginState(state) {
				if state.Buckets != nil {
					m.state.Buckets = state.Buckets
				}
				if state.Blocks != nil {
					m.state.Blocks = state.Blocks
				}
				m.needsReset = false
			}
		}
	}
	return m
}

func validLoginState(state loginState) bool {
	if len(state.Buckets) > 1024 || len(state.Blocks) > 128 {
		return false
	}
	for key, bucket := range state.Buckets {
		if len(key) > 512 || bucket == nil || len(bucket.Failures) > 100 {
			return false
		}
	}
	for key, block := range state.Blocks {
		ip, err := netip.ParseAddr(block.IP)
		if err != nil || ip.Zone() != "" || key != block.RuleID+"\x00"+block.IP || len(block.Ports) == 0 || len(block.Ports) > 16 {
			return false
		}
		for _, port := range block.Ports {
			if port < 1 || port > 65535 {
				return false
			}
		}
	}
	return true
}

func (m *loginMonitor) update(rules []config.LoginRule) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.needsReset {
		if err := m.reset(); err != nil {
			m.log.Error("损坏的登录状态无法清理来源封禁", "err", err)
		} else {
			m.needsReset = false
		}
	}
	m.rules = map[string]config.LoginRule{}
	for _, rule := range rules {
		if rule.Enabled && platformMatches(rule.Match.Platforms) {
			rule.Match = rule.Match.Defaults()
			m.rules[rule.ID] = rule
		}
	}
	for key := range m.state.Buckets {
		id, _, _ := strings.Cut(key, "\x00")
		if _, ok := m.rules[id]; !ok {
			delete(m.state.Buckets, key)
		}
	}
	m.reconcile(m.now())
}

func parseSSHAttempt(line *pb.LogLine) (loginAttempt, bool) {
	match := sshAttemptPattern.FindStringSubmatch(line.GetContent())
	if match == nil {
		return loginAttempt{}, false
	}
	ip, err := netip.ParseAddr(match[4])
	if err != nil || ip.Zone() != "" {
		return loginAttempt{}, false
	}
	timestamp := time.UnixMilli(line.GetTs())
	first, _, _ := strings.Cut(line.GetContent(), " ")
	if parsed, err := time.Parse(time.RFC3339Nano, first); err == nil {
		timestamp = parsed
	} else if prefix := syslogTimePattern.FindStringSubmatch(line.GetContent()); prefix != nil {
		if parsed, err := time.ParseInLocation("Jan _2 15:04:05", prefix[1], time.Local); err == nil {
			timestamp = time.Date(timestamp.Year(), parsed.Month(), parsed.Day(), parsed.Hour(), parsed.Minute(), parsed.Second(), 0, time.Local)
			if timestamp.After(time.UnixMilli(line.GetTs()).Add(24 * time.Hour)) {
				timestamp = timestamp.AddDate(-1, 0, 0)
			}
		}
	}
	return loginAttempt{IP: ip.Unmap(), User: match[3], Method: match[2], Failed: match[1] == "Failed", Time: timestamp}, true
}

func trustedLoginIP(ip netip.Addr, values []string) bool {
	for _, value := range values {
		if address, err := netip.ParseAddr(value); err == nil && address.Unmap() == ip {
			return true
		}
		if prefix, err := netip.ParsePrefix(value); err == nil {
			if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
				prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
			}
			if prefix.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func allowedLoginHour(hour, start, end int) bool {
	if start == end {
		return true
	}
	if start < end {
		return hour >= start && hour < end
	}
	return hour >= start || hour < end
}

func (m *loginMonitor) observe(source string, lines []*pb.LogLine) []*pb.RptSecurityEvent {
	if source != "secure" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	var events []*pb.RptSecurityEvent
	changed := false
	for _, line := range lines {
		attempt, ok := parseSSHAttempt(line)
		if !ok {
			continue
		}
		for _, rule := range m.rules {
			match := rule.Match
			if trustedLoginIP(attempt.IP, match.TrustedIPs) || slices.Contains(match.UserExclude, attempt.User) || attempt.Time.Before(now.Add(-time.Duration(match.WindowSec)*time.Second)) || attempt.Time.After(now.Add(30*time.Second)) {
				continue
			}
			trigger := "ssh_bruteforce"
			if !attempt.Failed {
				location, _ := time.LoadLocation(match.Timezone)
				if !match.OffHoursEnabled || allowedLoginHour(attempt.Time.In(location).Hour(), match.AllowedStartHour, match.AllowedEndHour) {
					continue
				}
				trigger = "ssh_off_hours"
			}
			key := rule.ID + "\x00" + attempt.IP.String() + "\x00" + trigger
			bucket := m.state.Buckets[key]
			if bucket == nil {
				if len(m.state.Buckets) >= 1024 {
					oldestKey := ""
					for candidate, existing := range m.state.Buckets {
						if oldestKey == "" || existing.LastSeen < m.state.Buckets[oldestKey].LastSeen {
							oldestKey = candidate
						}
					}
					delete(m.state.Buckets, oldestKey)
				}
				bucket = &loginBucket{}
				m.state.Buckets[key] = bucket
			}
			changed = true
			bucket.LastSeen = now.UnixMilli()
			cutoff := now.Add(-time.Duration(match.WindowSec) * time.Second).UnixMilli()
			bucket.Failures = slices.DeleteFunc(bucket.Failures, func(ts int64) bool { return ts < cutoff })
			if attempt.Failed {
				bucket.Failures = append(bucket.Failures, attempt.Time.UnixMilli())
				if len(bucket.Failures) > match.FailureThreshold {
					bucket.Failures = bucket.Failures[len(bucket.Failures)-match.FailureThreshold:]
				}
				if len(bucket.Failures) < match.FailureThreshold {
					continue
				}
			}
			if bucket.LastAlert != 0 && now.UnixMilli()-bucket.LastAlert < int64(match.CooldownSec)*1000 {
				continue
			}
			bucket.LastAlert = now.UnixMilli()
			detail := map[string]any{"source_ip": attempt.IP.String(), "account": attempt.User, "method": attempt.Method, "trigger": trigger, "window_sec": match.WindowSec, "failure_count": len(bucket.Failures), "login_time": attempt.Time.Format(time.RFC3339), "timezone": match.Timezone}
			action := "alert_only"
			if attempt.Failed && hasAction(rule.Actions, "block_ip") {
				block := loginBlock{RuleID: rule.ID, IP: attempt.IP.String(), Ports: slices.Clone(match.SSHPorts), Expires: now.Add(time.Duration(match.BlockDurationSec) * time.Second).UnixMilli()}
				blockKey := rule.ID + "\x00" + block.IP
				if len(m.state.Blocks) >= 128 && m.state.Blocks[blockKey].IP == "" {
					detail["error"] = "来源封禁数量达到上限"
					action = "block_failed"
				} else {
					m.state.Blocks[blockKey] = block
					err := m.save()
					if err == nil {
						err = m.apply(block, true)
					}
					if err != nil {
						if rollbackErr := m.apply(block, false); rollbackErr != nil {
							block.Expires = now.UnixMilli()
							m.state.Blocks[blockKey] = block
							err = fmt.Errorf("%w; 清理失败，将重试: %v", err, rollbackErr)
						} else {
							delete(m.state.Blocks, blockKey)
						}
						delete(m.applied, blockKey)
						detail["error"] = err.Error()
						action = "block_failed"
					} else {
						m.applied[blockKey] = true
						action = "blocked_ip"
						detail["blocked_until"] = block.Expires
						detail["ssh_ports"] = block.Ports
					}
				}
			}
			payload, _ := json.Marshal(detail)
			typ := "login_crack"
			if !attempt.Failed {
				typ = "login_anomaly"
			}
			events = append(events, &pb.RptSecurityEvent{RuleId: rule.ID, RuleName: rule.Name, Type: typ, Severity: processSeverity(rule.Severity), Detail: string(payload), ActionTaken: action, EventTs: attempt.Time.UnixMilli()})
		}
	}
	if changed {
		if err := m.save(); err != nil {
			m.log.Error("登录检测状态保存失败", "err", err)
		}
	}
	return events
}

func (m *loginMonitor) tick() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reconcile(m.now())
}

func (m *loginMonitor) reconcile(now time.Time) {
	if m.needsReset {
		if err := m.reset(); err != nil {
			m.log.Warn("登录来源封禁清理失败，将重试", "err", err)
			return
		}
		m.needsReset = false
	}
	changed := false
	for key, block := range m.state.Blocks {
		rule, enabled := m.rules[block.RuleID]
		ip, err := netip.ParseAddr(block.IP)
		valid := err == nil && enabled && hasAction(rule.Actions, "block_ip") && block.Expires > now.UnixMilli() && block.Expires <= now.Add(time.Hour).UnixMilli() && slices.Equal(block.Ports, rule.Match.SSHPorts) && !trustedLoginIP(ip.Unmap(), rule.Match.TrustedIPs)
		if !valid {
			if err := m.apply(block, false); err != nil {
				m.log.Warn("登录来源封禁解除失败，将重试", "err", err)
				continue
			}
			delete(m.state.Blocks, key)
			delete(m.applied, key)
			changed = true
		} else if !m.applied[key] {
			if err := m.apply(block, true); err != nil {
				m.log.Warn("登录来源封禁恢复失败，将重试", "err", err)
			} else {
				m.applied[key] = true
			}
		}
	}
	if changed {
		if err := m.save(); err != nil {
			m.log.Error("来源封禁状态保存失败", "err", err)
		}
	}
}

func (m *loginMonitor) save() error {
	data, err := json.Marshal(m.state)
	if err != nil {
		return fmt.Errorf("编码登录防护状态: %w", err)
	}
	return writePrivateAtomic(m.path, data)
}
