// Package configguard pins local configuration and authenticated policy snapshots
// independently of their editable shadow files. It does not establish trust
// against root/Administrator or a compromised Agent process.
package configguard

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/alinksec/alinksec-agent/internal/config"
	"github.com/alinksec/alinksec-agent/internal/securestate"
	"gopkg.in/yaml.v3"
)

const MaxPolicyBytes = 1 << 20
const maxRecordBytes = 2 << 20
const MaxEvents = 64

type Event struct {
	ID             string `json:"id"`
	Time           int64  `json:"time"`
	File           string `json:"file"`
	Path           string `json:"path"`
	PathTruncated  bool   `json:"path_truncated,omitempty"`
	Reason         string `json:"reason"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
	ObservedSHA256 string `json:"observed_sha256,omitempty"`
	Action         string `json:"action"`
	Shadow         string `json:"shadow"`
}

type record struct {
	Version       int               `json:"version"`
	ConfigPath    string            `json:"config_path"`
	Agent         []byte            `json:"agent"`
	AgentSHA      string            `json:"agent_sha256"`
	Policy        []byte            `json:"policy,omitempty"`
	PolicySHA     string            `json:"policy_sha256"`
	PolicyVersion string            `json:"policy_version,omitempty"`
	PolicyReady   bool              `json:"policy_ready"`
	Events        []Event           `json:"events,omitempty"`
	Last          map[string]string `json:"last,omitempty"`
}

// Store owns the OS lock until Close; an offline admin apply cannot race a
// running Agent or a second installer. Its mutex serializes checks and mTLS sync.
type Store struct {
	mu        sync.Mutex
	work, dir string
	r         record
	diskSHA   string
	release   func()
	closed    bool
	dirty     bool
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func Open(workDir, configPath string) (*Store, *config.Config, error) {
	return open(workDir, configPath, nil)
}

// Create installs a validated initial configuration under the same lock used by
// run/apply. It never truncates a link target or overwrites an existing install.
func Create(workDir, configPath string, cfg *config.Config) (*Store, *config.Config, error) {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot encode initial configuration")
	}
	if _, err := config.Parse(data); err != nil {
		return nil, nil, err
	}
	return open(workDir, configPath, data)
}

func open(workDir, configPath string, initialData []byte) (*Store, *config.Config, error) {
	work, err := absolute(workDir)
	if err != nil {
		return nil, nil, err
	}
	path, err := absolute(configPath)
	if err != nil {
		return nil, nil, err
	}
	if len(work) > 4096 || len(path) > 4096 {
		return nil, nil, fmt.Errorf("configuration paths exceed 4096 bytes")
	}
	if err := parentDirectories(filepath.Join(work, "placeholder"), true); err != nil {
		return nil, nil, err
	}
	if err := securestate.PrivateDir(work); err != nil {
		return nil, nil, err
	}
	dir := filepath.Join(work, "config-integrity")
	if err := realParents(filepath.Join(dir, "placeholder")); err != nil && !os.IsNotExist(err) {
		return nil, nil, err
	}
	unlock, err := securestate.Lock(dir)
	if err != nil {
		return nil, nil, err
	}
	s := &Store{work: work, dir: dir, release: unlock}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	b, err := ReadFile(s.recordPath(), maxRecordBytes)
	if initialData != nil {
		if !os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("existing trusted configuration; use run or offline config apply")
		}
		for _, name := range []string{"config-integrity.enabled", "state.yml", filepath.Join("certs", "client.crt")} {
			if _, e := os.Lstat(filepath.Join(work, name)); e == nil || !os.IsNotExist(e) {
				return nil, nil, fmt.Errorf("existing Agent installation; use run or offline config apply")
			}
		}
		if e := writeAtomic(path, initialData); e != nil {
			return nil, nil, e
		}
	}
	if os.IsNotExist(err) {
		// A surviving marker prevents a removed/corrupt record from silently
		// becoming a new trust-on-first-use enrollment.
		if _, e := os.Lstat(filepath.Join(work, "config-integrity.enabled")); e == nil || !os.IsNotExist(e) {
			return nil, nil, fmt.Errorf("trusted configuration record missing; restore protected state")
		}
		initial, e := ReadFile(path, config.MaxConfigBytes)
		if e != nil {
			return nil, nil, fmt.Errorf("initial configuration must be a bounded ordinary file: %w", e)
		}
		if _, e = config.Parse(initial); e != nil {
			return nil, nil, e
		}
		s.r = record{Version: 1, ConfigPath: path, Agent: initial, AgentSHA: sum(initial), PolicySHA: sum(nil), Last: map[string]string{}}
		if err := s.persist(); err != nil {
			return nil, nil, err
		}
	} else if err != nil {
		return nil, nil, fmt.Errorf("cannot read trusted configuration record: %w", err)
	} else {
		if err := privateFile(s.recordPath()); err != nil {
			return nil, nil, err
		}
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		if d.Decode(&s.r) != nil || d.Decode(new(any)) != io.EOF || s.r.Version != 1 || s.r.ConfigPath != path || len(s.r.Agent) > config.MaxConfigBytes || len(s.r.Policy) > MaxPolicyBytes || s.r.AgentSHA != sum(s.r.Agent) || s.r.PolicySHA != sum(s.r.Policy) || len(s.r.Events) > MaxEvents {
			return nil, nil, fmt.Errorf("trusted configuration record invalid or bound to a different --config path")
		}
		if s.r.Last == nil {
			s.r.Last = map[string]string{}
		}
		s.diskSHA = sum(b)
	}
	if err := s.ensureMarker(); err != nil {
		return nil, nil, err
	}
	cfg, err := config.Parse(s.r.Agent)
	if err != nil {
		return nil, nil, fmt.Errorf("trusted configuration cannot be parsed")
	}
	if err := s.Check(); err != nil {
		return nil, nil, err
	}
	ok = true
	return s, cfg, nil
}

func (s *Store) recordPath() string { return filepath.Join(s.dir, "record.json") }
func (s *Store) ensureMarker() error {
	path := filepath.Join(s.work, "config-integrity.enabled")
	if b, err := ReadFile(path, 128); err == nil {
		if string(b) != "alinksec-config-integrity-v1\n" {
			return fmt.Errorf("invalid configuration protection marker")
		}
		return privateFile(path)
	} else if !os.IsNotExist(err) {
		return err
	}
	return writeAtomic(path, []byte("alinksec-config-integrity-v1\n"))
}

func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		s.release()
	}
}
func (s *Store) persist() error {
	s.dirty = true
	b, err := json.Marshal(s.r)
	if err != nil || len(b) > maxRecordBytes {
		return fmt.Errorf("trusted configuration record exceeds limit")
	}
	if err := writeAtomic(s.recordPath(), b); err != nil {
		return fmt.Errorf("persist trusted configuration: %w", err)
	}
	s.diskSHA = sum(b)
	s.dirty = false
	return nil
}

// Policy returns a copy so readers cannot mutate the trusted snapshot.
func (s *Store) Policy() ([]byte, string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.r.Policy...), s.r.PolicyVersion, s.r.PolicyReady
}
func (s *Store) Events() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.r.Events...)
}

// SetPolicy is called only after validation of an authenticated PolicySync (or
// the explicitly documented one-time legacy migration). Commit authority first;
// shadow replacement is best effort and never determines active protection.
func (s *Store) SetPolicy(data []byte, version string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(data) > MaxPolicyBytes || len(version) > 256 {
		return fmt.Errorf("policy unavailable or too large")
	}
	old := s.r
	s.r.Policy = append([]byte(nil), data...)
	s.r.PolicySHA = sum(data)
	s.r.PolicyVersion = version
	s.r.PolicyReady = true
	if err := s.persist(); err != nil {
		s.r = old
		return err
	}
	if len(data) > 0 {
		_ = writeAtomic(filepath.Join(s.work, "policy.json"), data)
	}
	return nil
}

// ReplaceAgent is an explicit offline administrator operation. It requires the
// same process lock as Open, validates before commit, and is effective on restart.
func (s *Store) ReplaceAgent(data []byte) error {
	if _, err := config.Parse(data); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("configuration store closed")
	}
	old := s.r
	s.r.Agent = append([]byte(nil), data...)
	s.r.AgentSHA = sum(data)
	if err := s.persist(); err != nil {
		s.r = old
		return err
	}
	// A committed baseline remains authoritative even if an external mount is
	// read-only. The next check records that the shadow could not be repaired.
	_ = writeAtomic(s.r.ConfigPath, data)
	return nil
}

func (s *Store) ClearEnrollToken() error {
	s.mu.Lock()
	c, err := config.Parse(s.r.Agent)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if c.EnrollToken == "" {
		return nil
	}
	c.EnrollToken = ""
	b, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("cannot encode cleared bootstrap configuration")
	}
	return s.ReplaceAgent(b)
}

func (s *Store) event(file, path, reason, expected, observed, shadow string) error {
	fingerprint := reason + ":" + expected + ":" + observed + ":" + shadow
	if s.r.Last[file] == fingerprint {
		return nil
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return err
	}
	// Bound the displayed path so even maximally JSON-escaped paths fit the
	// server's 8 KiB event limit and all 64 events fit the 2 MiB trusted record.
	truncated := len(path) > 1024
	if truncated {
		path = path[:1024]
		for !utf8.ValidString(path) {
			path = path[:len(path)-1]
		}
	}
	e := Event{ID: hex.EncodeToString(id), Time: time.Now().UnixMilli(), File: file, Path: path, PathTruncated: truncated, Reason: reason, ExpectedSHA256: expected, ObservedSHA256: observed, Action: "trusted_config_in_use", Shadow: shadow}
	s.r.Last[file] = fingerprint
	s.r.Events = append(s.r.Events, e)
	if len(s.r.Events) > MaxEvents {
		s.r.Events = append([]Event(nil), s.r.Events[len(s.r.Events)-MaxEvents:]...)
	}
	return nil
}

// Check hashes actual bytes (not mtime/size) and restores safe regular shadows.
// A bad/missing shadow is never parsed into the active configuration.
func (s *Store) Check() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("configuration store closed")
	}
	before, _ := json.Marshal(s.r)
	b, err := ReadFile(s.recordPath(), maxRecordBytes)
	if err != nil || sum(b) != s.diskSHA || privateFile(s.recordPath()) != nil {
		if err := s.event("trusted_state", s.recordPath(), "trusted_state_changed", s.diskSHA, "", "memory_snapshot_retained"); err != nil {
			return err
		}
	}
	if err := s.ensureMarker(); err != nil {
		if err := s.event("marker", filepath.Join(s.work, "config-integrity.enabled"), "marker_invalid", "", "", "memory_snapshot_retained"); err != nil {
			return err
		}
	}
	type target struct {
		name, path string
		data       []byte
		limit      int
	}
	items := []target{{"agent.yml", s.r.ConfigPath, s.r.Agent, config.MaxConfigBytes}}
	if s.r.PolicyReady {
		items = append(items, target{"policy.json", filepath.Join(s.work, "policy.json"), s.r.Policy, MaxPolicyBytes})
	}
	for _, t := range items {
		data, readErr := ReadFile(t.path, t.limit)
		if len(t.data) == 0 && os.IsNotExist(readErr) {
			delete(s.r.Last, t.name)
			continue
		}
		if readErr == nil && bytes.Equal(data, t.data) && privateFile(t.path) == nil {
			delete(s.r.Last, t.name)
			continue
		}
		reason, observed := "content_changed", ""
		if readErr != nil {
			reason = "missing_or_unsafe_file"
		} else if bytes.Equal(data, t.data) {
			reason = "unsafe_permissions"
			observed = sum(data)
		} else {
			observed = sum(data)
		}
		shadow := "blocked"
		if len(t.data) == 0 {
			shadow = "unapproved_file_ignored"
		} else if writeAtomic(t.path, t.data) == nil {
			shadow = "restored"
		}
		if err := s.event(t.name, t.path, reason, sum(t.data), observed, shadow); err != nil {
			return err
		}
	}
	after, _ := json.Marshal(s.r)
	if s.dirty || !bytes.Equal(before, after) || err != nil || sum(b) != s.diskSHA || privateFile(s.recordPath()) != nil {
		return s.persist()
	}
	return nil
}
