package yara_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/configguard"
	"github.com/alinksec/alinksec-agent/internal/yara"
	"github.com/alinksec/alinksec-agent/internal/yara/yaratest"
)

func feed(data []byte) func(context.Context, io.Writer) error {
	return func(ctx context.Context, w io.Writer) error { _, err := w.Write(data); return err }
}
func TestDefaultBuildDoesNotClaimNativeYARA(t *testing.T) {
	if yara.Contract() != 0 {
		t.Skip("native build")
	}
	cfg := yaratest.Config(t, `rule always {condition:true}`)
	c := yara.New(cfg, configguard.ReadFile)
	if c.Status().State != "unsupported" || c.Realtime() {
		t.Fatal(c.Status())
	}
	if _, err := c.Probe(context.Background()); yara.Code(err) != "yara_not_built" {
		t.Fatal(err)
	}
}
func TestNativeYARAWorker(t *testing.T) {
	cfg, v := yaratest.Native(t)
	c := yara.New(cfg, configguard.ReadFile)
	checks := []string{"libyara-4.5.8-static", "worker-os-allocation-limit-192MiB", "exact-rule-source-sha256"}
	m, err := c.Scan(context.Background(), v, feed([]byte(yaratest.Marker)))
	if err != nil || len(m) != 2 || m[0].Rule != "AlinkSec_Native_Marker" || m[0].Severity != 4 || m[1].Rule != "AlinkSec_Secondary" {
		t.Fatalf("matches=%+v err=%v", m, err)
	}
	checks = append(checks, "native-text-hex-regex-integer-read-math-module-and-multiple-rules")
	if m, err = c.Scan(context.Background(), v, feed([]byte("ordinary content"))); err != nil || len(m) != 0 {
		t.Fatalf("clean=%v err=%v", m, err)
	}
	checks = append(checks, "real-clean-file")
	if m, err = c.Scan(context.Background(), v+"changed", feed([]byte(yaratest.Marker))); len(m) != 0 || yara.Code(err) != "yara_version_changed" {
		t.Fatal(m, err)
	}
	if err = os.WriteFile(cfg.RulesFile, []byte(`rule changed {condition:true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if m, err = c.Scan(context.Background(), v, feed([]byte(yaratest.Marker))); len(m) != 0 || yara.Code(err) != "yara_rules_changed" {
		t.Fatal(m, err)
	}
	checks = append(checks, "version-and-source-change-refuse-findings")
	for _, sample := range []struct{ source, code string }{
		{`rule broken {condition:}`, "yara_compile_error"},
		{`include "must-not-be-read.yar" rule x {condition:true}`, "yara_compile_error"},
		{`import "unavailable_module" rule x {condition:true}`, "yara_compile_error"},
		{`import "hash" rule x {condition:true}`, "yara_compile_error"},
		{`rule bad {meta: severity="high" condition:true}`, "yara_compile_error"},
		{"// no rules", "yara_empty_rules"},
	} {
		x := yara.New(yaratest.Config(t, sample.source), configguard.ReadFile)
		if _, err := x.Probe(context.Background()); yara.Code(err) != sample.code || x.Status().State != "unavailable" {
			t.Fatalf("%s err=%v status=%+v", sample.source, err, x.Status())
		}
	}
	checks = append(checks, "compile-failure-include-module-metadata-empty-source-refuse-readiness")
	var source strings.Builder
	for i := 0; i < 33; i++ {
		source.WriteString("rule Rule_")
		source.WriteByte(byte('A' + i/26))
		source.WriteByte(byte('A' + i%26))
		source.WriteString(" {condition:true}\n")
	}
	x := yara.New(yaratest.Config(t, source.String()), configguard.ReadFile)
	version, err := x.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if m, err = x.Scan(context.Background(), version, feed(nil)); len(m) != 0 || yara.Code(err) != "yara_match_limit" {
		t.Fatalf("limit matches=%v err=%v", m, err)
	}
	checks = append(checks, "matching-rule-limit-rejects-partial-results")
	x = yara.New(yaratest.Config(t, `rule Expensive {condition:for all i in (0..1000000000) : (uint8(i % filesize)==65)}`), configguard.ReadFile)
	version, err = x.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	start := time.Now()
	m, err = x.Scan(ctx, version, feed(bytes.Repeat([]byte("A"), 1024)))
	cancel()
	if len(m) != 0 || yara.Code(err) != "yara_timeout" || time.Since(start) > 2*time.Second {
		t.Fatal(m, err, time.Since(start))
	}
	// A killed native child cannot poison the parent or the next scan.
	if err = os.WriteFile(cfg.RulesFile, []byte(yaratest.Rules), 0600); err != nil {
		t.Fatal(err)
	}
	if m, err = c.Scan(context.Background(), v, feed([]byte(yaratest.Marker))); err != nil || len(m) != 2 {
		t.Fatal(m, err)
	}
	checks = append(checks, "parent-deadline-kills-native-work-and-next-scan-recovers")
	if dest := os.Getenv("ALINKSEC_YARA_WORKER_EVIDENCE_FILE"); dest != "" {
		data, _ := json.MarshalIndent(map[string]any{"passed": true, "os": runtime.GOOS, "arch": runtime.GOARCH, "version": v, "checks": checks, "status": c.Status()}, "", "  ")
		if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dest, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
