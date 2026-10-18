package windowslogin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alinksec/alinksec-agent/internal/config"
	"github.com/alinksec/alinksec-agent/internal/securestate"
)

const maxStateBytes = 1 << 20
const maxEvents = 64
const batchSize = 128

type Reader interface {
	Latest() (Record, error)
	Find(uint64) (Record, error)
	After(uint64, uint64, int) ([]Record, error)
	Audit() (success, failure bool, err error)
}
type Block struct {
	Key     string `json:"key"`
	IP      string `json:"ip"`
	Ports   []int  `json:"ports"`
	Expires int64  `json:"expires"`
	Created int64  `json:"created"`
	RuleID  string `json:"rule_id"`
	EventID string `json:"event_id"`
}
type Firewall interface {
	Apply(Block) error
	Remove(string) error
	Close() error
	Active() (int, bool)
}
type Event struct {
	ID       string `json:"id"`
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Type     string `json:"type"`
	Severity int    `json:"severity"`
	Detail   string `json:"detail"`
	Action   string `json:"action"`
	Time     int64  `json:"time"`
}
type bucket struct {
	Failures  []int64 `json:"failures"`
	LastAlert int64   `json:"last_alert"`
	LastSeen  int64   `json:"last_seen"`
}
type state struct {
	Version     int                `json:"version"`
	Initialized bool               `json:"initialized"`
	Generation  string             `json:"generation"`
	Cursor      uint64             `json:"cursor"`
	Anchor      string             `json:"anchor"`
	PolicyHash  string             `json:"policy_hash"`
	PolicySince int64              `json:"policy_since"`
	Buckets     map[string]*bucket `json:"buckets"`
	Blocks      map[string]Block   `json:"blocks"`
	Events      []Event            `json:"events"`
	Gaps        uint64             `json:"gaps"`
	Discarded   uint64             `json:"discarded"`
}
type Status struct {
	State           string `json:"state"`
	Issue           string `json:"issue"`
	LastPoll        int64  `json:"last_poll_at"`
	LastEvent       int64  `json:"last_event_at"`
	Cursor          uint64 `json:"cursor"`
	AuditSuccess    bool   `json:"audit_success"`
	AuditFailure    bool   `json:"audit_failure"`
	ActiveBlocks    int    `json:"active_blocks"`
	BlockFailures   uint64 `json:"block_failures"`
	CoverageGaps    uint64 `json:"coverage_gaps"`
	DiscardedEvents uint64 `json:"discarded_events"`
	Rules           int    `json:"rules"`
	RetainedEvents  int    `json:"retained_events"`
}
type Engine struct {
	mu           sync.Mutex
	path, server string
	reader       Reader
	firewall     Firewall
	log          *slog.Logger
	s            state
	status       Status
	rules        []config.LoginRule
	now          func() time.Time
	write        func(string, any, int) error
	loadErr      error
	applied      map[string]int64
}

func newEngine(dir, server string, log *slog.Logger, r Reader, f Firewall) *Engine {
	e := &Engine{path: filepath.Join(dir, "state.json"), server: server, reader: r, firewall: f, log: log, now: time.Now, write: securestate.WriteJSONLimit, status: Status{State: "starting"}, applied: map[string]int64{}}
	e.s = state{Version: 1, Buckets: map[string]*bucket{}, Blocks: map[string]Block{}}
	if err := securestate.PrivateDir(dir); err != nil {
		e.loadErr = err
		return e
	}
	var s state
	err := securestate.ReadJSONLimit(e.path, &s, maxStateBytes)
	if err == nil {
		if validState(s) {
			e.s = s
		} else {
			e.loadErr = fmt.Errorf("invalid login journal")
		}
	} else if !os.IsNotExist(err) {
		e.loadErr = err
	}
	return e
}
func validState(s state) bool {
	if s.Version != 1 || len(s.Buckets) > 128 || len(s.Blocks) > 128 || len(s.Events) > maxEvents || s.Buckets == nil || s.Blocks == nil {
		return false
	}
	if s.Initialized && (!hexSize(s.Generation, 32) || (s.Cursor != 0 && !hexSize(s.Anchor, 64))) {
		return false
	}
	if s.PolicyHash != "" && !hexSize(s.PolicyHash, 64) {
		return false
	}
	for k, b := range s.Buckets {
		if len(k) > 512 || b == nil || len(b.Failures) > 100 {
			return false
		}
	}
	for k, b := range s.Blocks {
		ip, err := netip.ParseAddr(b.IP)
		if err != nil || !safeSource(ip) || b.Key != k || len(k) > 512 || !hexSize(b.EventID, 64) || len(b.Ports) == 0 || len(b.Ports) > 16 || b.Expires <= b.Created || b.Expires-b.Created > 3600000 {
			return false
		}
		for _, p := range b.Ports {
			if p < 1 || p > 65535 {
				return false
			}
		}
	}
	for _, v := range s.Events {
		if !hexSize(v.ID, 64) || len(v.Detail) > 8192 || len(v.RuleID) > 128 || len(v.RuleName) > 512 {
			return false
		}
	}
	return true
}
func hexSize(s string, n int) bool {
	if len(s) != n {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
func safeSource(a netip.Addr) bool {
	return a.IsValid() && a.Zone() == "" && a.IsGlobalUnicast() && !a.IsLoopback() && !a.IsLinkLocalUnicast()
}
func generation() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func clone(s state) state { b, _ := json.Marshal(s); var v state; _ = json.Unmarshal(b, &v); return v }
func (e *Engine) commit(next state) error {
	if err := e.write(e.path, next, maxStateBytes); err != nil {
		return err
	}
	e.s = next
	return nil
}

func (e *Engine) Update(rules []config.LoginRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var selected []config.LoginRule
	for _, r := range rules {
		if r.Enabled && r.Match.WindowsContract == 1 && slices.Equal(r.Match.Platforms, []string{"windows"}) {
			r.Match = r.Match.Defaults()
			selected = append(selected, r)
		}
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].ID < selected[j].ID })
	data, _ := json.Marshal(selected)
	h := sha256.Sum256(data)
	hash := hex.EncodeToString(h[:])
	e.rules = selected
	if e.loadErr != nil {
		e.fail("journal_invalid")
		return
	}
	// Withdraw a newly disallowed source even if the journal disk is failing.
	if err := e.reconcile(); err != nil {
		return
	}
	if err := e.syncPolicy(hash); err != nil {
		e.fail("persist_failed")
		return
	}
	if len(selected) == 0 {
		e.status.State = "disabled"
		e.status.Issue = ""
	}
}
func (e *Engine) syncPolicy(hash string) error {
	if hash == e.s.PolicyHash {
		return nil
	}
	next := clone(e.s)
	next.PolicyHash = hash
	next.PolicySince = e.now().UnixMilli()
	next.Buckets = map[string]*bucket{}
	if len(e.rules) == 0 {
		next.Initialized = false
		next.Cursor = 0
		next.Anchor = ""
	}
	return e.commit(next)
}
func (e *Engine) fail(issue string) { e.status.State = "failed"; e.status.Issue = issue }
func (e *Engine) Run(ctx context.Context) (result error) {
	defer func() {
		if err := e.firewall.Close(); err != nil {
			e.log.Error("close Windows login filters", "err", err)
			result = err
		}
	}()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		if ctx.Err() != nil {
			return nil
		}
		e.Poll()
		if _, failed := e.firewall.Active(); failed {
			return fmt.Errorf("Windows login WFP cleanup requires owner process restart")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}
func (e *Engine) Poll() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.loadErr != nil {
		e.fail("journal_invalid")
		return
	}
	data, _ := json.Marshal(e.rules)
	h := sha256.Sum256(data)
	if err := e.syncPolicy(hex.EncodeToString(h[:])); err != nil {
		e.fail("persist_failed")
		return
	}
	if err := e.reconcile(); err != nil {
		return
	}
	if len(e.rules) == 0 {
		e.status.State = "disabled"
		return
	}
	e.status.LastPoll = e.now().UnixMilli()
	success, failure, err := e.reader.Audit()
	e.status.AuditSuccess = success
	e.status.AuditFailure = failure
	if err != nil {
		e.fail("audit_query_failed")
		return
	}
	latest, err := e.reader.Latest()
	if err != nil {
		e.fail("security_read_failed")
		return
	}
	next := clone(e.s)
	if !next.Initialized {
		next.Initialized = true
		next.Generation = generation()
		next.Cursor = latest.ID
		next.Anchor = latest.Fingerprint
		if err := e.commit(next); err != nil {
			e.fail("persist_failed")
			return
		}
		e.coverage(success, failure, false)
		return
	}
	if next.Cursor != 0 {
		anchor, err := e.reader.Find(next.Cursor)
		if err != nil {
			e.fail("security_read_failed")
			return
		}
		if latest.ID < next.Cursor || anchor.ID != next.Cursor || anchor.Fingerprint != next.Anchor {
			// A log clear/overwrite cannot join two generations of failure counters.
			next.Generation = generation()
			next.Cursor = latest.ID
			next.Anchor = latest.Fingerprint
			next.Buckets = map[string]*bucket{}
			next.Gaps++
			if err := e.commit(next); err != nil {
				e.fail("persist_failed")
				return
			}
			e.status.State = "degraded"
			e.status.Issue = "log_gap"
			return
		}
	}
	records, err := e.reader.After(next.Cursor, latest.ID, batchSize)
	if err != nil {
		e.fail("event_query_failed")
		return
	}
	bufferFull := false
	for _, r := range records {
		if r.ID <= next.Cursor || r.ID > latest.ID {
			e.fail("event_order_invalid")
			return
		}
		if r.Attempt != nil {
			var before state
			if len(next.Events)+len(e.rules) > maxEvents {
				before = clone(next)
			}
			if err := e.observe(&next, r); err != nil {
				next = before
				bufferFull = true
				break
			}
		}
		next.Cursor = r.ID
		next.Anchor = r.Fingerprint
		e.status.LastEvent = r.Time.UnixMilli()
	}
	// Other Security event types may be skipped by the login XPath. Only advance
	// to latest when the batch was exhausted, retaining a native record anchor.
	behind := bufferFull || len(records) == batchSize
	if !behind {
		next.Cursor = latest.ID
		next.Anchor = latest.Fingerprint
	}
	if err := e.commit(next); err != nil {
		e.fail("persist_failed")
		return
	}
	if err := e.reconcile(); err != nil {
		return
	}
	if bufferFull {
		e.fail("event_buffer_full")
		return
	}
	e.coverage(success, failure, behind)
}
func (e *Engine) coverage(success, failure, behind bool) {
	e.status.State = "polling"
	e.status.Issue = ""
	switch {
	case e.status.BlockFailures > 0:
		e.status.State = "degraded"
		e.status.Issue = "block_failed"
	case e.s.Discarded > 0:
		e.status.State = "degraded"
		e.status.Issue = "event_retention_exceeded"
	case !success || !failure:
		e.status.State = "degraded"
		e.status.Issue = "audit_disabled"
	case behind:
		e.status.State = "behind"
		e.status.Issue = "backlog"
	case e.s.Gaps > 0:
		e.status.State = "degraded"
		e.status.Issue = "log_gap"
	}
}
func trusted(ip netip.Addr, values []string) bool {
	for _, v := range values {
		if a, err := netip.ParseAddr(v); err == nil && a.Unmap() == ip {
			return true
		}
		if p, err := netip.ParsePrefix(v); err == nil {
			if p.Addr().Is4In6() && p.Bits() >= 96 {
				p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
			}
			if p.Contains(ip) {
				return true
			}
		}
	}
	return false
}
func excludedAccount(values []string, account string) bool {
	for _, v := range values {
		if strings.EqualFold(v, account) {
			return true
		}
	}
	return false
}
func allowed(hour, start, end int) bool {
	if start == end {
		return true
	}
	if start < end {
		return hour >= start && hour < end
	}
	return hour >= start || hour < end
}
func (e *Engine) observe(s *state, r Record) error {
	a := r.Attempt
	now := e.now()
	ts := r.Time.UnixMilli()
	for _, rule := range e.rules {
		m := rule.Match
		if ts < s.PolicySince || r.Time.Before(now.Add(-time.Duration(m.WindowSec)*time.Second)) || r.Time.After(now.Add(30*time.Second)) || trusted(a.IP, m.TrustedIPs) || excludedAccount(m.UserExclude, a.Account) || !slices.Contains(m.WindowsLogonTypes, a.LogonType) {
			continue
		}
		trigger := "windows_bruteforce"
		typ := "login_crack"
		if !a.Failed {
			location, err := time.LoadLocation(m.Timezone)
			if err != nil || !m.OffHoursEnabled || allowed(r.Time.In(location).Hour(), m.AllowedStartHour, m.AllowedEndHour) {
				continue
			}
			trigger = "windows_off_hours"
			typ = "login_anomaly"
		}
		key := rule.ID + "\x00" + a.IP.String() + "\x00" + trigger
		b := s.Buckets[key]
		if b == nil {
			if len(s.Buckets) >= 128 {
				old := ""
				for k, v := range s.Buckets {
					if old == "" || v.LastSeen < s.Buckets[old].LastSeen {
						old = k
					}
				}
				delete(s.Buckets, old)
			}
			b = &bucket{}
			s.Buckets[key] = b
		}
		b.LastSeen = now.UnixMilli()
		cut := now.Add(-time.Duration(m.WindowSec) * time.Second).UnixMilli()
		b.Failures = slices.DeleteFunc(b.Failures, func(t int64) bool { return t < cut })
		if a.Failed {
			b.Failures = append(b.Failures, ts)
			if len(b.Failures) > m.FailureThreshold {
				b.Failures = b.Failures[len(b.Failures)-m.FailureThreshold:]
			}
			if len(b.Failures) < m.FailureThreshold {
				continue
			}
		}
		if b.LastAlert != 0 && now.UnixMilli()-b.LastAlert < int64(m.CooldownSec)*1000 {
			continue
		}
		b.LastAlert = now.UnixMilli()
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%s", s.Generation, r.ID, rule.ID)))
		id := hex.EncodeToString(sum[:])
		detail := map[string]any{"id": id, "source_ip": a.IP.String(), "account": a.Account, "logon_type": a.LogonType, "event_id": 4624, "record_id": r.ID, "generation": s.Generation, "trigger": trigger, "window_sec": m.WindowSec, "failure_count": len(b.Failures), "login_time": r.Time.Format(time.RFC3339Nano), "timezone": m.Timezone, "status": a.Status, "sub_status": a.SubStatus}
		action := "alert_only"
		if a.Failed {
			detail["event_id"] = 4625
		}
		if a.Failed && slices.Contains(rule.Actions, "block_ip") {
			k := rule.ID + "\x00" + a.IP.String()
			if len(s.Blocks) < 128 || s.Blocks[k].Key != "" {
				s.Blocks[k] = Block{Key: k, IP: a.IP.String(), Ports: slices.Clone(m.WindowsPorts), Created: now.UnixMilli(), Expires: now.Add(time.Duration(m.BlockDurationSec) * time.Second).UnixMilli(), RuleID: rule.ID, EventID: id}
				action = "block_pending"
				detail["blocked_until"] = s.Blocks[k].Expires
				detail["windows_ports"] = m.WindowsPorts
			} else {
				action = "block_failed"
				detail["error"] = "block_limit"
			}
		}
		payload, _ := json.Marshal(detail)
		sev := rule.Severity
		if sev < 1 || sev > 5 {
			sev = 3
		}
		if len(s.Events) == maxEvents {
			return fmt.Errorf("unacknowledged event buffer full")
		}
		s.Events = append(s.Events, Event{ID: id, RuleID: rule.ID, RuleName: rule.Name, Type: typ, Severity: sev, Detail: string(payload), Action: action, Time: ts})
	}
	return nil
}
func (e *Engine) managementSources() ([]netip.Addr, error) {
	host, _, err := net.SplitHostPort(e.server)
	if err != nil {
		return nil, fmt.Errorf("management_address_invalid")
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a.Unmap()}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("management_resolution_failed")
	}
	return ips, nil
}
func (e *Engine) reconcile() error {
	next := clone(e.s)
	changed := false
	now := e.now().UnixMilli()
	checked := false
	var management []netip.Addr
	var managementErr error
	for k, b := range next.Blocks {
		var rule *config.LoginRule
		for i := range e.rules {
			if e.rules[i].ID == b.RuleID {
				rule = &e.rules[i]
				break
			}
		}
		valid := rule != nil && slices.Contains(rule.Actions, "block_ip") && slices.Equal(rule.Match.WindowsPorts, b.Ports) && !trusted(netip.MustParseAddr(b.IP), rule.Match.TrustedIPs) && b.Expires > now && b.Created <= now+30000 && b.Expires-now <= 3600000 && b.Expires-b.Created <= int64(rule.Match.BlockDurationSec)*1000
		action := "blocked_ip"
		var err error
		if !valid {
			err = e.firewall.Remove(k)
			delete(e.applied, k)
			action = "block_expired"
		} else if e.applied[k] != b.Expires {
			if !checked {
				management, managementErr = e.managementSources()
				checked = true
			}
			err = managementErr
			for _, a := range management {
				if a.Unmap().String() == b.IP {
					err = fmt.Errorf("management_source")
					break
				}
			}
			if err == nil {
				err = e.firewall.Apply(b)
			}
			if err == nil {
				e.applied[k] = b.Expires
			}
		}
		if err != nil {
			e.status.BlockFailures++
			action = "block_failed"
			if removeErr := e.firewall.Remove(k); removeErr != nil {
				e.fail("firewall_cleanup_failed")
				return removeErr
			}
			delete(e.applied, k)
			valid = false
		}
		for i := range next.Events {
			v := &next.Events[i]
			if v.ID == b.EventID && v.Action == "block_pending" {
				if err != nil {
					var d map[string]any
					_ = json.Unmarshal([]byte(v.Detail), &d)
					msg := err.Error()
					if len(msg) > 512 {
						msg = msg[:512]
					}
					d["error"] = msg
					p, _ := json.Marshal(d)
					v.Detail = string(p)
				}
				v.Action = action
				changed = true
			}
		}
		if !valid {
			delete(next.Blocks, k)
			changed = true
		}
	}
	if changed {
		if err := e.commit(next); err != nil {
			e.fail("persist_failed")
			return err
		}
	}
	return nil
}
func (e *Engine) Events() []Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	var result []Event
	for _, v := range e.s.Events {
		if v.Action != "block_pending" {
			result = append(result, v)
		}
	}
	return result
}
func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.status
	s.Cursor = e.s.Cursor
	s.CoverageGaps = e.s.Gaps
	s.DiscardedEvents = e.s.Discarded
	s.Rules = len(e.rules)
	s.RetainedEvents = len(e.s.Events)
	var failed bool
	s.ActiveBlocks, failed = e.firewall.Active()
	if failed {
		s.State = "failed"
		s.Issue = "firewall_cleanup_failed"
	}
	return s
}
func (e *Engine) StatusJSON() string { b, _ := json.Marshal(e.Status()); return string(b) }

// ExecutionContract is zero on platforms which cannot read Security or use WFP.
func ExecutionContract() uint32 { return platformContract() }
func New(workDir, server string, log *slog.Logger) *Engine {
	if platformContract() == 0 {
		return nil
	}
	return newEngine(filepath.Join(workDir, "windows-login"), server, log, newReader(), newFirewall())
}

// Receipt removes only identities committed by the authenticated server.
// A failed write retains the journal; reconnect/retry sends the same identities.
func (e *Engine) Receipt(ids []string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(ids) > maxEvents {
		return fmt.Errorf("receipt limit")
	}
	for _, id := range ids {
		if !hexSize(id, 64) {
			return fmt.Errorf("invalid receipt")
		}
	}
	next := clone(e.s)
	next.Events = slices.DeleteFunc(next.Events, func(v Event) bool { return v.Action != "block_pending" && slices.Contains(ids, v.ID) })
	if err := e.commit(next); err != nil {
		e.fail("persist_failed")
		return err
	}
	return nil
}
