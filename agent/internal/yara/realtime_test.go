package yara

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const realtimeRules = `rule RealtimeMarker { strings: $s="realtime safe marker" condition: $s }`

func realtimeConfig(t testing.TB, source []byte) Config {
	t.Helper()
	if Contract() != 1 {
		if os.Getenv("ALINKSEC_YARA_NATIVE_REQUIRED") == "true" {
			t.Fatal("native YARA required")
		}
		t.Skip("requires native YARA")
	}
	path := filepath.Join(t.TempDir(), "approved.yar")
	if err := os.WriteFile(path, source, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(source)
	return Config{Enabled: true, Realtime: true, RulesFile: path, RulesSHA256: hex.EncodeToString(digest[:]), TimeoutSec: 10}
}

func TestNativeRealtimeProbeReuseKeepsFailuresAndExpires(t *testing.T) {
	c := New(realtimeConfig(t, []byte(realtimeRules)), readFixture)
	version, err := c.ProbeRealtime(context.Background())
	if err != nil || c.validatedAt.IsZero() || c.Status().State != "ready" {
		t.Fatal("initial real validation failed", err, c.Status())
	}
	_, err = c.Scan(context.Background(), version, func(context.Context, io.Writer) error { return os.ErrPermission })
	if Code(err) != "yara_read_failed_or_changed" {
		t.Fatal(err)
	}
	validatedAt, failed := c.validatedAt, c.Status()
	for n := 0; n < 5; n++ {
		v, err := c.ProbeRealtime(context.Background())
		s := c.Status()
		if err != nil || v != version || !c.validatedAt.Equal(validatedAt) || s.ObservedAt != failed.ObservedAt || s.LastIssue != failed.LastIssue || s.ScanFailures.LastAt != failed.ScanFailures.LastAt || s.Failures != 1 {
			t.Fatal("reuse refreshed readiness or erased failure", err, s)
		}
	}
	// Explicit health probes always validate using a new native worker.
	if _, err := c.Probe(context.Background()); err != nil || c.validatedAt.Equal(validatedAt) {
		t.Fatal("explicit probe reused validation", err)
	}
	c.validatedAt = time.Now().Add(-31 * time.Second)
	expired := c.validatedAt
	if _, err := c.ProbeRealtime(context.Background()); err != nil || c.validatedAt.Equal(expired) || time.Since(c.validatedAt) > time.Second {
		t.Fatal("expired validation was reused", err)
	}
	if c.Status().ScanFailures.Counts["yara_read_failed_or_changed"] != 1 {
		t.Fatal("real revalidation erased failure history")
	}
}

func TestNativeRealtimeProbeCancellationDoesNotReuseReadyState(t *testing.T) {
	reads := 0
	c := New(realtimeConfig(t, []byte(realtimeRules)), func(path string, limit int) ([]byte, error) {
		reads++
		return readFixture(path, limit)
	})
	if _, err := c.ProbeRealtime(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, validatedAt := reads, c.validatedAt
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if version, err := c.ProbeRealtime(ctx); version != "" || Code(err) != "yara_timeout" || reads != before || !c.validatedAt.Equal(validatedAt) {
		t.Fatal("canceled request reused readiness or read rules", version, err, reads)
	}
}

func TestNativeRealtimeProbeRejectsSourceChangesAndScanSwap(t *testing.T) {
	cfg := realtimeConfig(t, []byte(realtimeRules))
	c := New(cfg, readFixture)
	version, err := c.ProbeRealtime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	changed := []byte(realtimeRules + "\n// changed on disk")
	if err := os.WriteFile(cfg.RulesFile, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if v, err := c.ProbeRealtime(context.Background()); v != "" || Code(err) != "yara_rules_changed" || c.Status().State != "unavailable" {
		t.Fatal("cached readiness bypassed source pin", v, err, c.Status())
	}
	if err := os.WriteFile(cfg.RulesFile, []byte(realtimeRules), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ProbeRealtime(context.Background()); err != nil {
		t.Fatal(err)
	}
	matches, err := c.Scan(context.Background(), version, func(_ context.Context, sink io.Writer) error {
		if _, err := io.WriteString(sink, "realtime safe marker"); err != nil {
			return err
		}
		return os.WriteFile(cfg.RulesFile, changed, 0600)
	})
	if len(matches) != 0 || Code(err) != "yara_rules_changed" || c.Status().Failures != 1 {
		t.Fatal("source swap accepted native findings", matches, err, c.Status())
	}
}

func TestNativeRealtimeProbeTracksAtomicApprovedUpdates(t *testing.T) {
	_ = realtimeConfig(t, []byte(realtimeRules))
	var mu sync.Mutex
	source := realtimeRules
	downloaded := make(chan struct{}, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_, _ = io.WriteString(w, source)
		if source != realtimeRules {
			downloaded <- struct{}{}
		}
	}))
	defer server.Close()
	ca := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	c := NewWithUpdates(Config{Enabled: true, Realtime: true, UpdateURL: server.URL, UpdateCAFile: ca}, readFixture, work)
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	oldVersion, validatedAt := c.Status().Version, c.validatedAt
	if v, err := c.ProbeRealtime(context.Background()); err != nil || v != oldVersion || !c.validatedAt.Equal(validatedAt) {
		t.Fatal("approved update validation not reused", v, err)
	}
	updateCtx, cancelUpdate := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelUpdate()
	updated := make(chan error, 1)
	matches, err := c.Scan(context.Background(), oldVersion, func(_ context.Context, sink io.Writer) error {
		if _, err := io.WriteString(sink, "realtime safe marker"); err != nil {
			return err
		}
		mu.Lock()
		source = `rule NewMarker { strings: $s="new realtime safe marker" condition: $s }`
		mu.Unlock()
		go func() { updated <- c.Refresh(updateCtx) }()
		select {
		case <-downloaded:
		case <-updateCtx.Done():
			return updateCtx.Err()
		}
		select {
		case err := <-updated:
			t.Error("update finished while scan held the serial gate", err)
		default:
		}
		if c.Status().Version != oldVersion {
			t.Error("update replaced the active scan snapshot")
		}
		return nil
	})
	if err != nil || len(matches) != 1 || matches[0].Rule != "RealtimeMarker" {
		t.Fatal("serialized update interrupted the current scan", matches, err)
	}
	if err := <-updated; err != nil {
		t.Fatal("queued approved update failed", err)
	}
	newVersion, validatedAt := c.Status().Version, c.validatedAt
	if v, err := c.ProbeRealtime(context.Background()); err != nil || v == oldVersion || v != newVersion || !c.validatedAt.Equal(validatedAt) {
		t.Fatal("new exact version unavailable", v, err)
	}
	consumed := false
	if matches, err := c.Scan(context.Background(), oldVersion, func(context.Context, io.Writer) error {
		consumed = true
		return nil
	}); len(matches) != 0 || Code(err) != "yara_version_changed" || consumed {
		t.Fatal("stale version accepted after approved update", matches, err, consumed)
	}
	matches, err = c.Scan(context.Background(), newVersion, func(_ context.Context, sink io.Writer) error {
		_, err := io.WriteString(sink, "new realtime safe marker")
		return err
	})
	if err != nil || len(matches) != 1 || matches[0].Rule != "NewMarker" {
		t.Fatal("new snapshot did not detect", matches, err)
	}
	if err := os.WriteFile(filepath.Join(work, "yara-updates/current.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ProbeRealtime(context.Background()); Code(err) != "yara_rules_unavailable" {
		t.Fatal("ready reuse bypassed corrupt update snapshot", err)
	}
}

func BenchmarkNativeRealtimeProbeReuse(b *testing.B) {
	source := []byte(realtimeRules)
	if path := os.Getenv("ALINKSEC_YARA_REALTIME_BENCH_RULES"); path != "" {
		var err error
		source, err = os.ReadFile(path)
		if err != nil {
			b.Fatal(err)
		}
	}
	cfg := realtimeConfig(b, source)
	for _, reuse := range []bool{false, true} {
		name := "fresh-probe"
		if reuse {
			name = "reuse-ready"
		}
		b.Run(name, func(b *testing.B) {
			c := New(cfg, readFixture)
			if _, err := c.Probe(context.Background()); err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				probe := c.Probe
				if reuse {
					probe = c.ProbeRealtime
				}
				version, err := probe(ctx)
				if err == nil {
					var matches []Match
					matches, err = c.Scan(ctx, version, func(_ context.Context, sink io.Writer) error {
						_, err := io.WriteString(sink, strings.Repeat("ordinary harmless content\n", 40))
						return err
					})
					if len(matches) != 0 {
						b.Fatal("ordinary content matched", matches)
					}
				}
				cancel()
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
