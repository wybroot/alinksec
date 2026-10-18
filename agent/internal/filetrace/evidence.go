// Package filetrace correlates Windows file writes with process instances.
// File activity alone never triggers a response; guard supplies changed paths.
package filetrace

import (
	"context"
	"strings"
	"sync"
	"time"
)

const (
	maxObjects = 4096
	maxWrites  = 4096
	retention  = 120 * time.Second
)

type Identity struct {
	PID     uint32 `json:"pid"`
	Created uint64 `json:"created_filetime,string"`
	Image   string `json:"image"`
}

type Write struct {
	Path      string    `json:"path"`
	At        time.Time `json:"at"`
	Process   Identity  `json:"process"`
	Operation string    `json:"operation"`
}

type Result struct {
	Source  string    `json:"source"`
	Status  string    `json:"status"`
	Reason  string    `json:"reason,omitempty"`
	Process *Identity `json:"process,omitempty"`
	Writes  []Write   `json:"writes,omitempty"`
}

type native interface {
	start() error
	check() error
	close() error
}

type Monitor struct {
	mu      sync.Mutex
	roots   []string
	writes  []Write
	status  string
	reason  string
	since   time.Time
	window  time.Duration
	native  native
	changed chan struct{}
}

func New(workDir string) *Monitor {
	m := &Monitor{status: "disabled", changed: make(chan struct{}, 1)}
	m.native = newNative(m, workDir)
	return m
}

func (m *Monitor) Status() Result {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Result{Source: "windows_kernel_file_etw", Status: m.status, Reason: m.reason}
}

func (m *Monitor) Counters() map[string]uint64 {
	if n, ok := m.native.(interface{ counters() map[string]uint64 }); ok {
		return n.counters()
	}
	return map[string]uint64{}
}

// Configure resets the evidence epoch when policy roots change. Native capture
// is started only while the ransomware rule is enabled. Retention is bounded.
func (m *Monitor) Configure(roots []string, window time.Duration) {
	var normalized []string
	for _, p := range roots {
		p = cleanPath(p)
		if p != "" && len(normalized) < 64 {
			normalized = append(normalized, p)
		}
	}
	m.mu.Lock()
	if strings.Join(m.roots, "\x00") == strings.Join(normalized, "\x00") && m.window == window {
		m.mu.Unlock()
		return
	}
	m.window = window
	m.roots = normalized
	m.writes = nil
	m.since = time.Now()
	m.status = "starting"
	m.reason = ""
	if len(normalized) == 0 {
		m.status = "disabled"
	}
	if window > retention-10*time.Second {
		m.status = "unavailable"
		m.reason = "window_exceeds_retention"
	}
	m.mu.Unlock()
	select {
	case m.changed <- struct{}{}:
	default:
	}
}

// Run owns the native session. Any collection failure invalidates all evidence;
// recovery creates a fresh epoch, never reuses evidence across a capture gap.
func (m *Monitor) Run(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	defer m.native.close()
	var retry time.Time
	running := false
	for {
		m.mu.Lock()
		enabled := len(m.roots) > 0 && m.reason != "window_exceeds_retention"
		state := m.status
		m.mu.Unlock()
		if running && (!enabled || state != "ready") {
			if err := m.native.close(); err != nil {
				m.fail("session_cleanup_failed")
				retry = time.Now().Add(30 * time.Second)
			}
			running = false
			if state != "starting" && enabled {
				retry = time.Now().Add(30 * time.Second)
			}
		}
		if enabled && !running && time.Now().After(retry) {
			if err := m.native.start(); err != nil {
				m.fail("capture_start_failed: " + err.Error())
				retry = time.Now().Add(30 * time.Second)
			} else {
				m.mu.Lock()
				m.status = "ready"
				m.reason = ""
				m.since = time.Now()
				m.writes = nil
				m.mu.Unlock()
				running = true
			}
		}
		if running {
			if err := m.native.check(); err != nil {
				m.fail("capture_health_failed: " + err.Error())
				retry = time.Now().Add(30 * time.Second)
			}
		}
		select {
		case <-ctx.Done():
			m.fail("capture_stopped")
			return
		case <-m.changed:
		case <-tick.C:
		}
	}
}

func (m *Monitor) fail(reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status = "unavailable"
	m.reason = reason
	m.writes = nil
}

func cleanPath(p string) string {
	p = strings.ToLower(strings.ReplaceAll(p, "/", `\`))
	p = strings.TrimPrefix(p, `\\?\`)
	return strings.TrimRight(p, `\`)
}

func (m *Monitor) watched(path string) bool {
	path = cleanPath(path)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, root := range m.roots {
		if path == root || strings.HasPrefix(path, root+`\`) {
			return true
		}
	}
	return false
}

func (m *Monitor) observe(w Write) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.status != "ready" {
		return
	}
	w.Path = cleanPath(w.Path)
	cutoff := time.Now().Add(-retention)
	kept := m.writes[:0]
	for _, old := range m.writes {
		if old.At.After(cutoff) {
			kept = append(kept, old)
		}
	}
	m.writes = kept
	if len(m.writes) >= maxWrites {
		m.status = "unavailable"
		m.reason = "write_capacity_exceeded"
		m.writes = nil
		return
	}
	m.writes = append(m.writes, w)
}

func (m *Monitor) Lookup(paths []string, since time.Time) Result {
	if err := m.native.check(); err != nil {
		m.fail("capture_health_failed: " + err.Error())
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r := Result{Source: "windows_kernel_file_etw", Status: m.status, Reason: m.reason}
	if m.status != "ready" {
		return r
	}
	r.Status = "unattributed"
	if since.Before(m.since) || since.Before(time.Now().Add(-retention)) {
		r.Reason = "capture_gap"
		return r
	}
	if len(paths) == 0 || len(paths) > maxObjects {
		r.Reason = "invalid_file_set"
		return r
	}
	var identity *Identity
	for _, path := range paths {
		found := false
		for _, w := range m.writes {
			if w.Path != cleanPath(path) || w.At.Before(since) {
				continue
			}
			found = true
			if len(r.Writes) < 100 {
				r.Writes = append(r.Writes, w)
			}
			if w.Process.PID <= 4 || w.Process.Created == 0 || w.Process.Image == "" {
				r.Reason = "writer_identity_unavailable"
				return r
			}
			if identity != nil && *identity != w.Process {
				r.Status = "ambiguous"
				r.Reason = "multiple_writers"
				return r
			}
			p := w.Process
			identity = &p
		}
		if !found {
			r.Reason = "no_observed_write"
			return r
		}
	}
	r.Status = "attributed"
	r.Process = identity
	return r
}
