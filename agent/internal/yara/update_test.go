package yara

import (
	"bytes"
	"context"
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

func readFixture(path string, _ int) ([]byte, error) { return os.ReadFile(path) }

func TestUpdateStoreRejectsLinkedDirectory(t *testing.T) {
	root, target := t.TempDir(), t.TempDir()
	linked := filepath.Join(root, "linked")
	if err := os.Symlink(target, linked); err != nil {
		t.Skip("symlinks unavailable", err)
	}
	if err := privateUpdateDirectory(filepath.Join(linked, "yara-updates")); err == nil {
		t.Fatal("linked update parent accepted")
	}
	if _, err := os.Stat(filepath.Join(target, "yara-updates")); !os.IsNotExist(err) {
		t.Fatal("updater wrote through linked parent", err)
	}
}

func TestUpdateConfiguration(t *testing.T) {
	for _, cfg := range []Config{
		{Enabled: true, UpdateURL: "https://rules.example/approved.yar"},
		{Enabled: true, UpdateURL: "https://rules.example/approved.yar", UpdateIntervalSec: 300},
		{Enabled: true, UpdateURLs: []string{"https://rules.example/a.yar", "https://rules.example/b.yar"}},
	} {
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, cfg := range []Config{
		{Enabled: true, UpdateURL: "http://rules.example/approved.yar"},
		{Enabled: true, UpdateURL: "https://user:password@rules.example/rules.yar"},
		{Enabled: true, UpdateURL: "https://rules.example/rules.yar?key=private"},
		{Enabled: true, UpdateURL: "https://rules.example/rules.yar#part"},
		{Enabled: true, UpdateURL: "https://rules.example:0/rules.yar"},
		{Enabled: true, UpdateURL: "https://rules.example/rules.yar", UpdateIntervalSec: 299},
		{Enabled: true, UpdateURL: "https://rules.example/rules.yar", UpdateIntervalSec: 604801},
		{Enabled: true, UpdateURL: "https://rules.example/rules.yar", UpdateCAFile: "relative-ca.crt"},
		{Enabled: true, UpdateIntervalSec: 300},
		{Enabled: true, UpdateURL: "https://rules.example/rules.yar", RulesFile: "partial-bootstrap"},
		{Enabled: true, UpdateURL: "https://rules.example/a.yar", UpdateURLs: []string{"https://rules.example/b.yar"}},
		{Enabled: true, UpdateURLs: []string{"https://rules.example/a.yar", "https://rules.example/a.yar"}},
		{Enabled: true, UpdateURLs: []string{"https://rules.example/a.yar", "http://rules.example/b.yar"}},
		{Enabled: true, UpdateURLs: []string{""}},
		{Enabled: true, UpdateURLs: make([]string, 17)},
	} {
		if err := cfg.Validate(); err == nil {
			t.Fatalf("accepted invalid config: %+v", cfg)
		}
	}
}

func TestRuleDownloadBoundaries(t *testing.T) {
	var body = []byte(`rule Marker { condition: true }`)
	var status = 200
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/rules", http.StatusFound)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if _, err := fetchRules(context.Background(), server.URL+"/rules", nil); err == nil {
		t.Fatal("untrusted TLS certificate accepted")
	}
	if b, err := fetchRules(context.Background(), server.URL+"/rules", ca); err != nil || !bytes.Equal(b, body) {
		t.Fatal(err)
	}
	if _, err := fetchRules(context.Background(), server.URL+"/redirect", ca); err == nil {
		t.Fatal("redirect accepted")
	}
	for _, sample := range []struct {
		status int
		body   []byte
	}{
		{503, body}, {304, nil}, {200, nil}, {200, bytes.Repeat([]byte("x"), MaxRuleBytes+1)},
	} {
		status, body = sample.status, sample.body
		if _, err := fetchRules(context.Background(), server.URL+"/rules", ca); err == nil {
			t.Fatal("invalid download accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fetchRules(ctx, server.URL+"/rules", ca); err == nil {
		t.Fatal("cancelled download accepted")
	}
}

func TestNativeScheduledRulesBecomeDetectionAndSurviveFailure(t *testing.T) {
	if Contract() != 1 {
		if os.Getenv("ALINKSEC_YARA_NATIVE_REQUIRED") == "true" {
			t.Fatal("native build required")
		}
		t.Skip("requires native YARA")
	}
	const oldRules = `rule First { strings: $s="harmless old marker" condition: $s }`
	const newRules = `rule Second { strings: $s="harmless new marker" condition: $s }`
	var mu sync.Mutex
	source, status := oldRules, 200
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		requests++
		w.WriteHeader(status)
		_, _ = io.WriteString(w, source)
	}))
	defer server.Close()
	caPath := filepath.Join(t.TempDir(), "source-ca.crt")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Enabled: true, Realtime: true, UpdateURL: server.URL + "/approved.yar", UpdateCAFile: caPath, UpdateIntervalSec: 300, TimeoutSec: 5}
	work := t.TempDir()
	c := NewWithUpdates(cfg, readFixture, work)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(10 * time.Second)
	for c.Status().Update.SuccessAt == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if c.Status().State != "ready" || c.Status().Update.SuccessAt == 0 {
		t.Fatal(c.Status())
	}
	first := c.Status().Version
	scan := func(marker, expectedRule string) {
		t.Helper()
		v, err := c.Probe(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		matches, err := c.Scan(context.Background(), v, func(_ context.Context, w io.Writer) error { _, e := io.WriteString(w, marker); return e })
		if err != nil || len(matches) != 1 || matches[0].Rule != expectedRule {
			t.Fatalf("matches=%v err=%v", matches, err)
		}
	}
	scan("harmless old marker", "First")
	mu.Lock()
	source = newRules
	mu.Unlock()
	// Advance the recorded due time, then exercise the production scheduler path.
	c.mu.Lock()
	c.status.Update.NextCheckAt = time.Now().Unix() - 1
	c.mu.Unlock()
	c.refreshIfDue(context.Background())
	second := c.Status().Version
	if first == second || second == "" {
		t.Fatal("new rule source did not become active")
	}
	scan("harmless new marker", "Second")
	if _, err := c.Scan(context.Background(), first, func(_ context.Context, w io.Writer) error { _, e := io.WriteString(w, "harmless new marker"); return e }); Code(err) != "yara_version_changed" {
		t.Fatal("old task version accepted", err)
	}
	mu.Lock()
	before := requests
	mu.Unlock()
	c.refreshIfDue(context.Background())
	mu.Lock()
	after := requests
	mu.Unlock()
	if before != after {
		t.Fatal("scheduler ignored update interval")
	}
	for _, sample := range []struct {
		source string
		status int
	}{
		{"upstream unavailable", 503}, {"", 200}, {"rule broken {condition:}", 200}, {"bad\x00rule", 200}, {"bad\xffrule", 200},
		{"include \"unexpected.yar\"\n" + newRules, 200}, {strings.Repeat("X", MaxRuleBytes+1), 200},
	} {
		mu.Lock()
		source, status = sample.source, sample.status
		mu.Unlock()
		if err := c.Refresh(context.Background()); err == nil || c.Status().Update.LastIssue == "" {
			t.Fatal("bad source accepted", c.Status())
		}
		if c.Status().Version != second || c.Status().State != "ready" {
			t.Fatal("failed update disabled working rules", c.Status())
		}
		scan("harmless new marker", "Second")
	}
	// Stop the periodic runner, restart with the upstream still unavailable, and
	// prove the persisted snapshot, rather than an in-memory object, is used.
	cancel()
	<-done
	done = make(chan struct{})
	close(done)
	restarted := NewWithUpdates(cfg, readFixture, work)
	if v, err := restarted.Probe(context.Background()); err != nil || v != second || restarted.Status().Update.SuccessAt == 0 {
		t.Fatal(v, err, restarted.Status())
	}
	otherCfg := cfg
	otherCfg.UpdateURL = server.URL + "/other.yar"
	if _, err := NewWithUpdates(otherCfg, readFixture, work).Probe(context.Background()); err == nil {
		t.Fatal("snapshot for a different source reused")
	}
	mu.Lock()
	source, status = newRules, 200
	mu.Unlock()
	previous, _ := c.readSnapshot()
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	unchanged, _ := c.readSnapshot()
	if unchanged.ChangedAt != previous.ChangedAt || c.Status().Update.LastIssue != "" {
		t.Fatal("unchanged source republished or error not cleared")
	}
	if err := os.WriteFile(filepath.Join(work, "yara-updates", "current.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Probe(context.Background()); err == nil {
		t.Fatal("corrupted snapshot accepted")
	}
}

func TestNativeMultipleSourcesSwitchTogether(t *testing.T) {
	if Contract() != 1 {
		t.Skip("requires native YARA")
	}
	second := `rule SecondSource { strings: $s="harmless second source marker" condition: $s }`
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/first" {
			_, _ = io.WriteString(w, `rule FirstSource { strings: $s="harmless first source marker" condition: $s }`)
			return
		}
		_, _ = io.WriteString(w, second)
	}))
	defer server.Close()
	ca := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Enabled: true, UpdateURLs: []string{server.URL + "/first", server.URL + "/second"}, UpdateCAFile: ca}
	work := t.TempDir()
	c := NewWithUpdates(cfg, readFixture, work)
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	v, err := c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	matches, err := c.Scan(context.Background(), v, func(_ context.Context, w io.Writer) error {
		_, e := io.WriteString(w, "harmless first source marker; harmless second source marker")
		return e
	})
	if err != nil || len(matches) != 2 {
		t.Fatalf("matches=%v err=%v", matches, err)
	}
	second = `rule invalid { condition: }`
	if err := c.Refresh(context.Background()); err == nil {
		t.Fatal("partial update accepted")
	}
	if current, err := c.Probe(context.Background()); err != nil || current != v {
		t.Fatal("old complete snapshot lost", current, err)
	}
	cfg.UpdateURLs = []string{server.URL + "/first"}
	changed := NewWithUpdates(cfg, readFixture, work)
	if _, err := changed.Probe(context.Background()); err == nil {
		t.Fatal("changed source list reused old snapshot")
	}
}
