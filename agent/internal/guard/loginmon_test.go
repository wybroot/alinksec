package guard

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/config"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func loginTestRule() config.LoginRule {
	return config.LoginRule{ID: "login-test", Enabled: true, Severity: 3, Actions: []string{"alert"}, Match: config.LoginMatch{WindowSec: 60, FailureThreshold: 3, CooldownSec: 30, BlockDurationSec: 10, SSHPorts: []int{2222}, Timezone: "UTC", AllowedStartHour: 8, AllowedEndHour: 20}}
}

func sshLine(now time.Time, failed bool, user, ip string) *pb.LogLine {
	result := "Accepted"
	if failed {
		result = "Failed"
	}
	return &pb.LogLine{Ts: now.UnixMilli(), Content: fmt.Sprintf("%s host sshd[123]: %s password for %s from %s port 50000 ssh2", now.Format(time.RFC3339), result, user, ip)}
}

func testLoginMonitor(t *testing.T, rule config.LoginRule) (*loginMonitor, *time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 2, 21, 0, 0, 0, time.UTC)
	m := newLoginMonitor(t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)), func(loginBlock, bool) error { return nil })
	m.now = func() time.Time { return now }
	m.update([]config.LoginRule{rule})
	return m, &now
}

func TestSSHSlidingWindowCooldownAndTrustedSources(t *testing.T) {
	rule := loginTestRule()
	rule.Match.TrustedIPs = []string{"192.0.2.0/24", "::ffff:198.51.100.0/120"}
	rule.Match.UserExclude = []string{"backup"}
	m, now := testLoginMonitor(t, rule)
	for _, ignored := range []*pb.LogLine{sshLine(*now, true, "root", "192.0.2.8"), sshLine(*now, true, "root", "198.51.100.8"), sshLine(*now, true, "backup", "203.0.113.8"), sshLine(now.Add(-2*time.Minute), true, "root", "203.0.113.8")} {
		for i := 0; i < 3; i++ {
			if len(m.observe("secure", []*pb.LogLine{ignored})) != 0 {
				t.Fatal("ignored attempt alerted")
			}
		}
	}
	line := sshLine(*now, true, "root", "203.0.113.8")
	if len(m.observe("windows-security", []*pb.LogLine{line, line, line})) != 0 {
		t.Fatal("unsupported log source matched")
	}
	if len(m.observe("secure", []*pb.LogLine{line, line})) != 0 {
		t.Fatal("alert below threshold")
	}
	if e := m.observe("secure", []*pb.LogLine{line}); len(e) != 1 || e[0].GetActionTaken() != "alert_only" || e[0].GetType() != "login_crack" {
		t.Fatalf("threshold event = %v", e)
	}
	if len(m.observe("secure", []*pb.LogLine{line, line})) != 0 {
		t.Fatal("cooldown ignored")
	}
	if len(m.observe("secure", []*pb.LogLine{sshLine(*now, true, "root", "203.0.113.9")})) != 0 {
		t.Fatal("different sources shared counters")
	}
	*now = now.Add(61 * time.Second)
	line = sshLine(*now, true, "root", "203.0.113.8")
	if len(m.observe("secure", []*pb.LogLine{line, line})) != 0 {
		t.Fatal("expired failures counted")
	}
	if len(m.observe("secure", []*pb.LogLine{line})) != 1 {
		t.Fatal("new threshold did not alert")
	}
}

func TestSSHOffHoursTimezoneAndOvernightWindow(t *testing.T) {
	rule := loginTestRule()
	rule.Match.OffHoursEnabled = true
	rule.Actions = []string{"alert", "block_ip"}
	m, now := testLoginMonitor(t, rule)
	m.apply = func(loginBlock, bool) error { t.Fatal("successful off-hours login must not block source"); return nil }
	if e := m.observe("secure", []*pb.LogLine{sshLine(*now, false, "root", "203.0.113.8")}); len(e) != 1 || e[0].GetType() != "login_anomaly" || e[0].GetActionTaken() != "alert_only" {
		t.Fatalf("off-hours event = %v", e)
	}
	gssapi := sshLine(*now, false, "root", "203.0.113.10")
	gssapi.Content = strings.Replace(gssapi.Content, "Accepted password", "Accepted gssapi-with-mic", 1)
	if e := m.observe("secure", []*pb.LogLine{gssapi}); len(e) != 1 || e[0].GetType() != "login_anomaly" || e[0].GetActionTaken() != "alert_only" {
		t.Fatalf("off-hours GSSAPI event = %v", e)
	}
	rule.Match.Timezone = "Asia/Shanghai"
	rule.Match.AllowedStartHour = 22
	rule.Match.AllowedEndHour = 6
	m.update([]config.LoginRule{rule})
	if len(m.observe("secure", []*pb.LogLine{sshLine(*now, false, "root", "203.0.113.9")})) != 0 {
		t.Fatal("overnight allowed login alerted")
	}
	for _, tc := range []struct {
		hour, start, end int
		want             bool
	}{{8, 8, 20, true}, {20, 8, 20, false}, {23, 22, 6, true}, {5, 22, 6, true}, {6, 22, 6, false}, {12, 0, 0, true}, {23, 0, 24, true}} {
		if allowedLoginHour(tc.hour, tc.start, tc.end) != tc.want {
			t.Fatalf("hour window %+v", tc)
		}
	}
}

func TestSSHBlockPersistenceExpiryAndPolicyRemoval(t *testing.T) {
	for _, removal := range []string{"expiry", "disabled", "trusted", "alert-only", "ports"} {
		t.Run(removal, func(t *testing.T) {
			rule := loginTestRule()
			rule.Actions = []string{"alert", "block_ip"}
			m, now := testLoginMonitor(t, rule)
			var enabled, disabled int
			apply := func(b loginBlock, on bool) error {
				if on {
					enabled++
				} else {
					disabled++
				}
				return nil
			}
			m.apply = apply
			line := sshLine(*now, true, "root", "203.0.113.8")
			m.observe("secure", []*pb.LogLine{line, line})
			m = newLoginMonitor(filepath.Dir(m.path), m.log, apply)
			m.now = func() time.Time { return *now }
			m.update([]config.LoginRule{rule})
			if e := m.observe("secure", []*pb.LogLine{line}); len(e) != 1 || e[0].GetActionTaken() != "blocked_ip" || enabled != 1 {
				t.Fatalf("persisted window/block = %v", e)
			}
			m = newLoginMonitor(filepath.Dir(m.path), m.log, apply)
			m.now = func() time.Time { return *now }
			m.update([]config.LoginRule{rule})
			if enabled != 2 || len(m.observe("secure", []*pb.LogLine{line, line, line})) != 0 {
				t.Fatal("restart did not restore block/cooldown")
			}
			switch removal {
			case "expiry":
				*now = now.Add(11 * time.Second)
			case "disabled":
				rule.Enabled = false
			case "trusted":
				rule.Match.TrustedIPs = []string{"203.0.113.0/24"}
			case "alert-only":
				rule.Actions = []string{"alert"}
			case "ports":
				rule.Match.SSHPorts = []int{22}
			}
			m.update([]config.LoginRule{rule})
			m.tick()
			if disabled != 1 || len(m.state.Blocks) != 0 {
				t.Fatalf("block not removed: %s", removal)
			}
		})
	}
}

func TestSSHBlockFailureKeepsAlertAndRetriesFailedRemoval(t *testing.T) {
	rule := loginTestRule()
	rule.Actions = []string{"alert", "block_ip"}
	m, now := testLoginMonitor(t, rule)
	m.apply = func(_ loginBlock, enabled bool) error {
		if enabled {
			return errors.New("firewall denied")
		}
		return nil
	}
	line := sshLine(*now, true, "root", "203.0.113.8")
	if e := m.observe("secure", []*pb.LogLine{line, line, line}); len(e) != 1 || e[0].GetActionTaken() != "block_failed" || !strings.Contains(e[0].GetDetail(), "firewall denied") {
		t.Fatalf("failure falsely reported success: %v", e)
	}
	if len(m.state.Blocks) != 0 {
		t.Fatal("failed block retained")
	}
	*now = now.Add(31 * time.Second)
	line = sshLine(*now, true, "root", "203.0.113.8")
	m.apply = func(loginBlock, bool) error { return nil }
	m.observe("secure", []*pb.LogLine{line, line, line})
	*now = now.Add(11 * time.Second)
	m.apply = func(loginBlock, bool) error { return errors.New("temporarily denied") }
	m.tick()
	if len(m.state.Blocks) != 1 {
		t.Fatal("failed removal must retain retry metadata")
	}
	m.apply = func(loginBlock, bool) error { return nil }
	m.tick()
	if len(m.state.Blocks) != 0 {
		t.Fatal("removal retry failed")
	}
}

func TestSSHCorruptStateIsResetAndCleanupRetries(t *testing.T) {
	for _, data := range []string{"invalid", `{"buckets":{"bad":null}}`, `{"blocks":{"bad":{"ip":"not-an-ip"}}}`} {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "login-protection.json"), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		m := newLoginMonitor(root, slog.New(slog.NewTextHandler(io.Discard, nil)), func(loginBlock, bool) error { return nil })
		calls := 0
		m.reset = func() error {
			calls++
			if calls == 1 {
				return errors.New("retry")
			}
			return nil
		}
		m.update([]config.LoginRule{loginTestRule()})
		m.tick()
		if calls < 2 || m.needsReset {
			t.Fatal("corrupt firewall state not cleared")
		}
	}
}

func TestSSHPartialBlockRollbackIsPersistedAndRetried(t *testing.T) {
	rule := loginTestRule()
	rule.Actions = []string{"alert", "block_ip"}
	m, now := testLoginMonitor(t, rule)
	m.apply = func(block loginBlock, enabled bool) error {
		if enabled {
			data, err := os.ReadFile(m.path)
			var stored loginState
			if err != nil || json.Unmarshal(data, &stored) != nil || len(stored.Blocks) != 1 {
				t.Fatal("firewall changed before durable cleanup metadata was saved")
			}
		}
		return errors.New("partial firewall failure")
	}
	line := sshLine(*now, true, "root", "203.0.113.8")
	events := m.observe("secure", []*pb.LogLine{line, line, line})
	if len(events) != 1 || events[0].GetActionTaken() != "block_failed" || len(m.state.Blocks) != 1 {
		t.Fatal("partial failure lost cleanup metadata")
	}
	m.apply = func(loginBlock, bool) error { return nil }
	m.tick()
	if len(m.state.Blocks) != 0 {
		t.Fatal("failed partial block was not cleaned up")
	}
}

func TestSSHGuardRejectsManagementAndSpecialIPsBeforeFirewallChanges(t *testing.T) {
	g := New(&config.DecoyConfig{}, nil, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	g.SetServerAddr("203.0.113.8:9443")
	for _, ip := range []string{"203.0.113.8", "::ffff:203.0.113.8", "127.0.0.1", "::1", "169.254.1.1", "0.0.0.0"} {
		if err := g.applyLoginBlock(loginBlock{RuleID: "test", IP: ip, Ports: []int{22}}, true); err == nil {
			t.Fatalf("protected IP %s was eligible for blocking", ip)
		}
	}
}

func TestSSHParsesCanonicalIPv6AndSyslogTimestamp(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 10, 0, time.UTC)
	line := &pb.LogLine{Ts: now.UnixMilli(), Content: "Dec 31 23:59:59 host sshd[42]: Failed publickey for invalid user admin from 2001:db8::8 port 42 ssh2"}
	a, ok := parseSSHAttempt(line)
	if !ok || a.IP != netip.MustParseAddr("2001:db8::8") || a.User != "admin" || a.Time.Year() != 2025 {
		t.Fatalf("attempt=%+v, ok=%v", a, ok)
	}
	line.Content = "sshd: Failed password for root from invalid-ip port 42"
	if _, ok := parseSSHAttempt(line); ok {
		t.Fatal("invalid IP accepted")
	}
}
