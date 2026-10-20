// Package clamav streams bounded file snapshots to an administrator-managed,
// certificate-pinned local ClamAV service. It never starts or updates the daemon.
package clamav

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const MaxFileBytes int64 = 20 << 20

type Config struct {
	Enabled          bool   `yaml:"enabled"`
	Address          string `yaml:"address"`
	ServerCertSHA256 string `yaml:"server_cert_sha256"`
	Realtime         bool   `yaml:"realtime"`
	TimeoutSec       int    `yaml:"timeout_sec"`
}

func (c Config) Validate() error {
	if !c.Enabled {
		if c.Realtime {
			return errors.New("ClamAV realtime requires enabled")
		}
		return nil
	}
	host, port, err := net.SplitHostPort(c.Address)
	ip := net.ParseIP(host)
	n, pe := strconv.Atoi(port)
	pin, he := hex.DecodeString(c.ServerCertSHA256)
	if err != nil || ip == nil || !ip.IsLoopback() || pe != nil || n < 1 || n > 65535 || he != nil || len(pin) != sha256.Size || c.TimeoutSec < 0 || c.TimeoutSec > 30 {
		return errors.New("ClamAV requires a literal loopback address, SHA256 certificate pin and timeout 1..30 seconds")
	}
	return nil
}

type Status struct {
	State      string `json:"state"`
	Version    string `json:"version"`
	ObservedAt int64  `json:"observed_at"`
	Realtime   bool   `json:"realtime"`
	LastScanAt int64  `json:"last_scan_at"`
	LastIssue  string `json:"last_issue"`
	Scans      uint64 `json:"scans"`
	Failures   uint64 `json:"failures"`
}

type Client struct {
	cfg    Config
	mu     sync.Mutex
	status Status
	gate   chan struct{}
}

func New(cfg Config) *Client {
	s := Status{State: "disabled"}
	if cfg.Enabled {
		s.State = "starting"
		s.Realtime = cfg.Realtime
	}
	return &Client{cfg: cfg, status: s, gate: make(chan struct{}, 1)}
}
func (c *Client) Realtime() bool { return c != nil && c.cfg.Enabled && c.cfg.Realtime }
func (c *Client) Status() Status {
	if c == nil {
		return Status{State: "disabled"}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}
func (c *Client) StatusJSON() string { b, _ := json.Marshal(c.Status()); return string(b) }
func (c *Client) Run(ctx context.Context) {
	if c == nil || !c.cfg.Enabled {
		return
	}
	c.Probe(ctx)
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
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
	var e issue
	if errors.As(err, &e) {
		return string(e)
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		return "clamav_timeout"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "clamav_timeout"
	}
	return "clamav_unavailable"
}

func (c *Client) dial(ctx context.Context) (*tls.Conn, error) {
	if c == nil || !c.cfg.Enabled {
		return nil, issue("clamav_disabled")
	}
	if c.cfg.Validate() != nil {
		return nil, issue("clamav_invalid_config")
	}
	pin, _ := hex.DecodeString(c.cfg.ServerCertSHA256)
	config := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, // Strict leaf pin replaces public CA/DNS verification for literal loopback.
		VerifyConnection: func(s tls.ConnectionState) error {
			if len(s.PeerCertificates) == 0 {
				return issue("clamav_tls_identity")
			}
			cert := s.PeerCertificates[0]
			sum := sha256.Sum256(cert.Raw)
			now := time.Now()
			if subtle.ConstantTimeCompare(sum[:], pin) != 1 || now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				return issue("clamav_tls_identity")
			}
			allowed := len(cert.ExtKeyUsage) == 0
			for _, usage := range cert.ExtKeyUsage {
				if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
					allowed = true
				}
			}
			if !allowed {
				return issue("clamav_tls_identity")
			}
			return nil
		}}
	raw, err := (&tls.Dialer{NetDialer: &net.Dialer{}, Config: config}).DialContext(ctx, "tcp", c.cfg.Address)
	if err != nil {
		return nil, err
	}
	conn := raw.(*tls.Conn)
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	return conn, nil
}
func (c *Client) bounded(ctx context.Context) (context.Context, context.CancelFunc) {
	seconds := 10
	if c != nil && c.cfg.TimeoutSec > 0 {
		seconds = c.cfg.TimeoutSec
	}
	return context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
}
func reply(conn io.Reader) (string, error) {
	r := bufio.NewReaderSize(conn, 4097)
	b, err := r.ReadSlice(0)
	if err != nil || len(b) > 4096 || len(b) < 2 || !utf8.Valid(b[:len(b)-1]) {
		return "", issue("clamav_protocol")
	}
	s := string(b[:len(b)-1])
	for _, ch := range s {
		if unicode.IsControl(ch) {
			return "", issue("clamav_protocol")
		}
	}
	return s, nil
}
func (c *Client) version(ctx context.Context) (string, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if _, err = io.WriteString(conn, "zVERSION\x00"); err != nil {
		return "", err
	}
	s, err := reply(conn)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(s, "ClamAV ") || len(s) > 256 {
		return "", issue("clamav_protocol")
	}
	return s, nil
}
func (c *Client) Probe(ctx context.Context) (string, error) {
	ctx, cancel := c.bounded(ctx)
	defer cancel()
	v, err := c.version(ctx)
	if c != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.status.ObservedAt = time.Now().Unix()
		if err != nil {
			c.status.State = "unavailable"
			c.status.LastIssue = Code(err)
		} else {
			c.status.State = "ready"
			c.status.Version = v
		}
	}
	return v, err
}

type streamWriter struct {
	conn  io.Writer
	total int64
}

func (w *streamWriter) Write(p []byte) (int, error) {
	if w.total+int64(len(p)) > MaxFileBytes {
		return 0, issue("clamav_file_limit")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(p)))
	if _, err := w.conn.Write(header[:]); err != nil {
		return 0, err
	}
	n, err := w.conn.Write(p)
	w.total += int64(n)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}

// Scan accepts only the same validated descriptor bytes used for the SHA256
// action precondition. Version is the daemon's reported identity, not a corpus digest.
func (c *Client) Scan(ctx context.Context, expected string, consume func(io.Writer) error) (name string, err error) {
	if c == nil || !c.cfg.Enabled {
		return "", issue("clamav_disabled")
	}
	ctx, cancel := c.bounded(ctx)
	defer cancel()
	select {
	case c.gate <- struct{}{}:
		defer func() { <-c.gate }()
	case <-ctx.Done():
		return "", ctx.Err()
	}
	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.status.Scans++
		c.status.LastScanAt = time.Now().Unix()
		if err != nil {
			c.status.Failures++
			c.status.LastIssue = Code(err)
		} else {
			c.status.LastIssue = ""
		}
	}()
	v, err := c.Probe(ctx)
	if err != nil {
		return "", err
	}
	if expected == "" || v != expected {
		return "", issue("clamav_version_changed")
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if _, err = io.WriteString(conn, "zINSTREAM\x00"); err != nil {
		return "", err
	}
	if err = consume(&streamWriter{conn: conn}); err != nil {
		return "", err
	}
	if _, err = conn.Write([]byte{0, 0, 0, 0}); err != nil {
		return "", err
	}
	s, err := reply(conn)
	if err != nil {
		return "", err
	}
	switch {
	case s == "stream: OK":
	case strings.HasPrefix(s, "stream: ") && strings.HasSuffix(s, " FOUND"):
		name = strings.TrimSuffix(strings.TrimPrefix(s, "stream: "), " FOUND")
		if name == "" || len(name) > 255 {
			return "", issue("clamav_protocol")
		}
		if strings.HasPrefix(name, "Heuristics.Limits.Exceeded") || strings.HasPrefix(name, "Heuristics.Encrypted") {
			return "", issue("clamav_incomplete")
		}
	default:
		return "", issue("clamav_scan_error")
	}
	after, err := c.Probe(ctx)
	if err != nil {
		return "", err
	}
	if after != expected {
		return "", issue("clamav_version_changed")
	}
	return name, nil
}
