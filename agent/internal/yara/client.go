// Package yara runs statically linked native YARA in a disposable, bounded
// subprocess. Rules and file bytes travel over a pipe; workers open no targets.
package yara

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const MaxFileBytes int64 = 20 << 20
const MaxRuleBytes = 256 << 10

type Config struct {
	Enabled           bool     `yaml:"enabled"`
	Realtime          bool     `yaml:"realtime"`
	RulesFile         string   `yaml:"rules_file"`
	RulesSHA256       string   `yaml:"rules_sha256"`
	TimeoutSec        int      `yaml:"timeout_sec"`
	UpdateURL         string   `yaml:"update_url"`
	UpdateURLs        []string `yaml:"update_urls"`
	UpdateCAFile      string   `yaml:"update_ca_file"`
	UpdateIntervalSec int      `yaml:"update_interval_sec"`
}

func (c Config) Validate() error {
	if !c.Enabled {
		if c.Realtime {
			return errors.New("YARA realtime requires enabled")
		}
		return nil
	}
	if err := c.validateUpdate(); err != nil {
		return err
	}
	if c.hasUpdates() && c.RulesFile == "" && c.RulesSHA256 == "" && c.TimeoutSec >= 0 && c.TimeoutSec <= 30 {
		return nil
	}
	pin, err := hex.DecodeString(c.RulesSHA256)
	if err != nil || len(pin) != 32 || !filepath.IsAbs(c.RulesFile) || len(c.RulesFile) > 4096 || strings.ContainsRune(c.RulesFile, 0) || c.TimeoutSec < 0 || c.TimeoutSec > 30 {
		return errors.New("YARA requires an absolute rule source, SHA256 pin and timeout 1..30 seconds")
	}
	return nil
}

type Status struct {
	State        string       `json:"state"`
	Version      string       `json:"version"`
	ObservedAt   int64        `json:"observed_at"`
	Realtime     bool         `json:"realtime"`
	LastScanAt   int64        `json:"last_scan_at"`
	LastIssue    string       `json:"last_issue"`
	Scans        uint64       `json:"scans"`
	Failures     uint64       `json:"failures"`
	ScanFailures ScanFailures `json:"scan_failures"`
	Update       UpdateStatus `json:"update"`
}

// ScanFailures survives successful probes and scans until the Agent restarts.
// Only bounded issue codes are retained; file paths and raw errors never leave
// the scanner through readiness telemetry.
type ScanFailures struct {
	LastAt    int64             `json:"last_at"`
	LastIssue string            `json:"last_issue"`
	Counts    map[string]uint64 `json:"counts"`
}
type Match struct {
	Rule     string `json:"rule"`
	Severity int32  `json:"severity"`
}
type Client struct {
	cfg            Config
	read           func(string, int) ([]byte, error)
	mu             sync.Mutex
	status         Status
	gate           chan struct{}
	updateGate     chan struct{}
	updateDir      string
	updateFailures int
	validatedAt    time.Time
}

func Contract() uint32 {
	if nativeVersion() == "" {
		return 0
	}
	return 1
}
func New(cfg Config, read func(string, int) ([]byte, error)) *Client {
	return NewWithUpdates(cfg, read, "")
}

// NewWithUpdates stores validated upstream snapshots in the private Agent work
// directory. Static, digest-pinned rules continue to work without an updater.
func NewWithUpdates(cfg Config, read func(string, int) ([]byte, error), workDir string) *Client {
	s := Status{State: "disabled", ScanFailures: ScanFailures{Counts: make(map[string]uint64)}}
	if cfg.Enabled {
		s.State = "starting"
		s.Realtime = cfg.Realtime
	}
	if Contract() == 0 {
		s.State = "unsupported"
		s.LastIssue = "yara_not_built"
		s.Realtime = false
	}
	s.Update.Enabled = cfg.Enabled && cfg.hasUpdates() && Contract() == 1
	dir := ""
	if workDir != "" {
		dir = filepath.Join(workDir, "yara-updates")
	}
	return &Client{cfg: cfg, read: read, status: s, gate: make(chan struct{}, 1), updateGate: make(chan struct{}, 1), updateDir: dir}
}
func (c *Client) Realtime() bool {
	return c != nil && Contract() == 1 && c.cfg.Enabled && c.cfg.Realtime
}
func (c *Client) Status() Status {
	if c == nil {
		return Status{State: "disabled"}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.status
	s.ScanFailures.Counts = make(map[string]uint64, len(c.status.ScanFailures.Counts))
	for code, count := range c.status.ScanFailures.Counts {
		s.ScanFailures.Counts[code] = count
	}
	return s
}
func (c *Client) StatusJSON() string { b, _ := json.Marshal(c.Status()); return string(b) }
func (c *Client) Run(ctx context.Context) {
	if c == nil || !c.cfg.Enabled || Contract() == 0 {
		return
	}
	c.Probe(ctx)
	c.refreshIfDue(ctx)
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.refreshIfDue(ctx)
			c.Probe(ctx)
		}
	}
}

type issue string

func (e issue) Error() string { return string(e) }
func Code(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "yara_timeout"
	}
	var i issue
	if errors.As(err, &i) {
		return string(i)
	}
	return "yara_read_failed_or_changed"
}
func (c *Client) bounded(ctx context.Context) (context.Context, context.CancelFunc) {
	sec := 10
	if c != nil && c.cfg.TimeoutSec > 0 {
		sec = c.cfg.TimeoutSec
	}
	return context.WithTimeout(ctx, time.Duration(sec)*time.Second)
}
func (c *Client) rules() ([]byte, string, error) {
	if Contract() == 0 {
		return nil, "", issue("yara_not_built")
	}
	if c == nil || !c.cfg.Enabled {
		return nil, "", issue("yara_disabled")
	}
	if c.cfg.Validate() != nil || c.read == nil {
		return nil, "", issue("yara_invalid_config")
	}
	if c.cfg.hasUpdates() {
		if b, err := c.updatedRules(); err == nil {
			return ruleVersion(b)
		} else if !errors.Is(err, errNoUpdate) || c.cfg.RulesFile == "" {
			return nil, "", issue("yara_rules_unavailable")
		}
	}
	b, err := c.read(c.cfg.RulesFile, MaxRuleBytes)
	if err != nil || len(b) == 0 || len(b) > MaxRuleBytes || !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
		return nil, "", issue("yara_rules_unavailable")
	}
	sum := sha256.Sum256(b)
	digest := hex.EncodeToString(sum[:])
	if !strings.EqualFold(digest, c.cfg.RulesSHA256) {
		return nil, "", issue("yara_rules_changed")
	}
	return b, "YARA " + nativeVersion() + "/sha256:" + digest, nil
}
func (c *Client) observe(v string, err error) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status.ObservedAt = time.Now().Unix()
	if err != nil {
		c.status.State = "unavailable"
		c.status.LastIssue = Code(err)
	} else {
		c.status.State = "ready"
		c.status.Version = v
		c.status.LastIssue = ""
		c.validatedAt = time.Now()
	}
}
func (c *Client) lock(ctx context.Context) error {
	if c == nil {
		return issue("yara_disabled")
	}
	select {
	case c.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (c *Client) Probe(ctx context.Context) (v string, err error) {
	return c.probe(ctx, false)
}

// ProbeRealtime avoids a second native compilation immediately before Scan.
// It re-reads the approved source and only reuses a successful validation of
// that exact digest for 30 seconds. Scan still runs a disposable native worker
// and validates the source again before and after consuming file bytes.
func (c *Client) ProbeRealtime(ctx context.Context) (v string, err error) {
	return c.probe(ctx, true)
}

func (c *Client) probe(ctx context.Context, reuse bool) (v string, err error) {
	ctx, cancel := c.bounded(ctx)
	defer cancel()
	if err = c.lock(ctx); err != nil {
		return "", err
	}
	defer func() { <-c.gate }()
	reused := false
	defer func() {
		if err != nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		if !reused || err != nil {
			c.observe(v, err)
		}
	}()
	if err = ctx.Err(); err != nil {
		return "", err
	}
	rules, v, err := c.rules()
	if err != nil {
		return "", err
	}
	if reuse {
		c.mu.Lock()
		age := time.Since(c.validatedAt)
		reused = c.status.State == "ready" && c.status.Version == v && !c.validatedAt.IsZero() && age >= 0 && age < 30*time.Second
		c.mu.Unlock()
		if reused {
			if err = ctx.Err(); err != nil {
				return "", err
			}
			// A cached lookup must not refresh readiness or clear a scan failure.
			return v, nil
		}
	}
	_, err = runWorker(ctx, rules, true, nil)
	if err != nil {
		return "", err
	}
	return v, nil
}

// Scan serializes active and realtime work and pins the exact source digest.
// consume must finish identity validation before closing the input stream.
func (c *Client) Scan(ctx context.Context, expected string, consume func(context.Context, io.Writer) error) (matches []Match, err error) {
	if c == nil {
		return nil, issue("yara_disabled")
	}
	ctx, cancel := c.bounded(ctx)
	defer cancel()
	locked := false
	defer func() {
		if err != nil && ctx.Err() != nil {
			matches = nil
			err = ctx.Err()
		}
		c.mu.Lock()
		c.status.Scans++
		c.status.LastScanAt = time.Now().Unix()
		if err != nil {
			c.status.Failures++
			c.status.LastIssue = Code(err)
			c.status.ScanFailures.LastAt = c.status.LastScanAt
			c.status.ScanFailures.LastIssue = Code(err)
			c.status.ScanFailures.Counts[Code(err)]++
		} else {
			c.status.LastIssue = ""
		}
		c.mu.Unlock()
		if locked {
			<-c.gate
		}
	}()
	if err = c.lock(ctx); err != nil {
		return nil, err
	}
	locked = true
	rules, v, err := c.rules()
	if err != nil {
		c.observe("", err)
		return nil, err
	}
	if expected == "" || v != expected {
		return nil, issue("yara_version_changed")
	}
	matches, err = runWorker(ctx, rules, false, consume)
	if err != nil {
		return nil, err
	}
	// Re-read the configured source after scanning; a swap never accepts findings.
	_, after, err := c.rules()
	if err != nil {
		return nil, err
	}
	if after != expected {
		return nil, issue("yara_version_changed")
	}
	c.observe(v, nil)
	return matches, nil
}
