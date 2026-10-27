package yara

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/alinksec/alinksec-agent/internal/securestate"
)

// An approved HTTPS source is the update authority. Its address is local,
// configuration-guarded policy, never supplied by a platform scan command.
// Only source text is accepted; no includes, archives or compiled rule objects.
type UpdateStatus struct {
	Enabled     bool   `json:"enabled"`
	CheckedAt   int64  `json:"checked_at"`
	SuccessAt   int64  `json:"success_at"`
	ChangedAt   int64  `json:"changed_at"`
	NextCheckAt int64  `json:"next_check_at"`
	LastIssue   string `json:"last_issue"`
}

const updateRecordLimit = MaxRuleBytes*2 + 4096

type ruleSnapshot struct {
	SourceSHA256 string `json:"source_sha256"`
	SHA256       string `json:"sha256"`
	Rules        []byte `json:"rules"`
	CheckedAt    int64  `json:"checked_at"`
	ChangedAt    int64  `json:"changed_at"`
}

var errNoUpdate = errors.New("no snapshot for the configured YARA source")

func (c Config) validateUpdate() error {
	if c.UpdateURL != "" && len(c.UpdateURLs) != 0 || len(c.UpdateURLs) > 16 {
		return errors.New("YARA requires either one update_url or at most 16 update_urls")
	}
	if !c.hasUpdates() {
		if c.UpdateIntervalSec != 0 || c.UpdateCAFile != "" {
			return errors.New("YARA update options require an HTTPS source")
		}
		return nil
	}
	seen := map[string]bool{}
	for _, address := range c.updateAddresses() {
		u, err := url.Parse(address)
		if err != nil || len(address) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || seen[address] {
			return errors.New("YARA update source must be HTTPS without credentials, query or fragment")
		}
		seen[address] = true
		if port := u.Port(); port != "" {
			n, e := strconv.Atoi(port)
			if e != nil || n < 1 || n > 65535 {
				return errors.New("YARA update source port is invalid")
			}
		}
	}
	if c.UpdateCAFile != "" && (!filepath.IsAbs(c.UpdateCAFile) || len(c.UpdateCAFile) > 4096 || strings.ContainsRune(c.UpdateCAFile, 0)) {
		return errors.New("YARA update CA must be a local absolute path")
	}
	if c.UpdateIntervalSec != 0 && (c.UpdateIntervalSec < 300 || c.UpdateIntervalSec > 7*24*3600) {
		return errors.New("YARA update interval must be 300..604800 seconds")
	}
	return nil
}

func (c Config) hasUpdates() bool { return c.UpdateURL != "" || len(c.UpdateURLs) != 0 }
func (c Config) updateAddresses() []string {
	if c.UpdateURL != "" {
		return []string{c.UpdateURL}
	}
	return c.UpdateURLs
}
func (c Config) updateIdentity() string {
	return sourceDigest(strings.Join(c.updateAddresses(), "\x00"))
}

func (c Config) updateInterval() int64 {
	if c.UpdateIntervalSec == 0 {
		return 3600
	}
	return int64(c.UpdateIntervalSec)
}
func sourceDigest(address string) string {
	sum := sha256.Sum256([]byte(address))
	return hex.EncodeToString(sum[:])
}
func ruleVersion(b []byte) ([]byte, string, error) {
	if len(b) == 0 || len(b) > MaxRuleBytes || !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
		return nil, "", issue("yara_rules_unavailable")
	}
	sum := sha256.Sum256(b)
	return b, "YARA " + nativeVersion() + "/sha256:" + hex.EncodeToString(sum[:]), nil
}
func (c *Client) readSnapshot() (ruleSnapshot, error) {
	var record ruleSnapshot
	if c.updateDir == "" {
		return record, issue("yara_update_storage")
	}
	b, err := c.read(filepath.Join(c.updateDir, "current.json"), updateRecordLimit)
	if errors.Is(err, os.ErrNotExist) {
		return record, errNoUpdate
	}
	if err != nil {
		return record, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(&record); err != nil {
		return record, err
	}
	if d.Decode(new(any)) != io.EOF {
		return record, issue("yara_update_storage")
	}
	if record.SourceSHA256 != c.cfg.updateIdentity() {
		return record, errNoUpdate
	}
	_, version, err := ruleVersion(record.Rules)
	if err != nil || version != "YARA "+nativeVersion()+"/sha256:"+record.SHA256 || record.ChangedAt <= 0 || record.CheckedAt < record.ChangedAt || record.CheckedAt > time.Now().Unix()+300 {
		return record, issue("yara_update_storage")
	}
	return record, nil
}
func (c *Client) updatedRules() ([]byte, error) {
	r, err := c.readSnapshot()
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.status.Update.SuccessAt < r.CheckedAt {
		if c.status.Update.CheckedAt < r.CheckedAt {
			c.status.Update.CheckedAt = r.CheckedAt
		}
		c.status.Update.SuccessAt = r.CheckedAt
		c.status.Update.ChangedAt = r.ChangedAt
	}
	c.mu.Unlock()
	return r.Rules, nil
}

func (c *Client) refreshIfDue(ctx context.Context) {
	c.mu.Lock()
	due := c.status.Update.Enabled && time.Now().Unix() >= c.status.Update.NextCheckAt
	c.mu.Unlock()
	if due {
		_ = c.Refresh(ctx)
	}
}

// Refresh fetches and compiles a complete candidate before replacing the last
// working snapshot. Failed downloads, compilation and writes leave it usable.
// Update errors do not turn a working, older rule set into a "ready/latest" claim.
func (c *Client) Refresh(ctx context.Context) (err error) {
	if c == nil || !c.cfg.Enabled || !c.cfg.hasUpdates() {
		return issue("yara_disabled")
	}
	if Contract() != 1 {
		return issue("yara_not_built")
	}
	if c.cfg.Validate() != nil || c.read == nil {
		return issue("yara_invalid_config")
	}
	select {
	case c.updateGate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-c.updateGate }()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	defer func() {
		now := time.Now().Unix()
		c.mu.Lock()
		defer c.mu.Unlock()
		c.status.Update.CheckedAt = now
		delay := c.cfg.updateInterval()
		if err != nil {
			if c.updateFailures < 8 {
				c.updateFailures++
			}
			retry := int64(300) << uint(c.updateFailures-1)
			if retry < delay {
				delay = retry
			}
			c.status.Update.LastIssue = Code(err)
		} else {
			c.updateFailures = 0
			c.status.Update.SuccessAt = now
			c.status.Update.LastIssue = ""
		}
		c.status.Update.NextCheckAt = now + delay
	}()
	if c.updateDir == "" {
		return issue("yara_update_storage")
	}
	var ca []byte
	if c.cfg.UpdateCAFile != "" {
		ca, err = c.read(c.cfg.UpdateCAFile, 64<<10)
		if err != nil || len(ca) == 0 {
			return issue("yara_update_download")
		}
	}
	var b []byte
	for i, address := range c.cfg.updateAddresses() {
		part, fetchErr := fetchRules(ctx, address, ca)
		if fetchErr != nil {
			return fetchErr
		}
		if i > 0 {
			b = append(b, '\n')
		}
		if len(b)+len(part) > MaxRuleBytes {
			return issue("yara_update_download")
		}
		b = append(b, part...)
	}
	_, _, err = ruleVersion(b)
	if err != nil {
		return issue("yara_update_download")
	}
	if err = c.lock(ctx); err != nil {
		return err
	}
	defer func() { <-c.gate }()
	compileCtx, compileCancel := c.bounded(ctx)
	defer compileCancel()
	if _, err = runWorker(compileCtx, b, true, nil); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	now := time.Now().Unix()
	sum := sha256.Sum256(b)
	next := ruleSnapshot{SourceSHA256: c.cfg.updateIdentity(), SHA256: hex.EncodeToString(sum[:]), Rules: b, CheckedAt: now, ChangedAt: now}
	if previous, e := c.readSnapshot(); e == nil && previous.SHA256 == next.SHA256 {
		next.ChangedAt = previous.ChangedAt
	}
	if err = privateUpdateDirectory(c.updateDir); err != nil {
		return issue("yara_update_storage")
	}
	if err = securestate.WriteJSONLimit(filepath.Join(c.updateDir, "current.json"), next, updateRecordLimit); err != nil {
		return issue("yara_update_storage")
	}
	c.mu.Lock()
	c.status.Update.ChangedAt = next.ChangedAt
	c.mu.Unlock()
	_, version, _ := ruleVersion(b)
	c.observe(version, nil)
	return nil
}

func privateUpdateDirectory(path string) error {
	// Check every existing parent before creating anything; the work directory
	// and its ancestors must not redirect updates through links/junctions.
	for p := path; ; p = filepath.Dir(p) {
		if info, err := os.Lstat(p); err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return issue("yara_update_storage")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return securestate.PrivateDir(path)
}

func fetchRules(ctx context.Context, address string, ca []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, issue("yara_update_download")
	}
	req.Header.Set("Accept", "text/plain, application/octet-stream")
	if req.URL.Hostname() == "api.github.com" {
		req.Header.Set("Accept", "application/vnd.github.raw+json")
	}
	req.Header.Set("User-Agent", "ALinkSec-YARA-Updater/1")
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(ca) != 0 {
		tlsConfig.RootCAs = x509.NewCertPool()
		if !tlsConfig.RootCAs.AppendCertsFromPEM(ca) {
			return nil, issue("yara_update_download")
		}
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, DisableKeepAlives: true, MaxResponseHeaderBytes: 16 << 10}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, err := client.Do(req)
	if err != nil {
		return nil, issue("yara_update_download")
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK || r.ContentLength > MaxRuleBytes {
		return nil, issue("yara_update_download")
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, MaxRuleBytes+1))
	if err != nil || len(b) == 0 || len(b) > MaxRuleBytes {
		return nil, issue("yara_update_download")
	}
	return b, nil
}
