package virusscan

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/alinksec/alinksec-agent/internal/configguard"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/yara"
	"github.com/alinksec/alinksec-agent/internal/yara/yaratest"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNativeYARAScan(t *testing.T) {
	cfg, version := yaratest.Native(t)
	client := yara.New(cfg, configguard.ReadFile)
	work, root := t.TempDir(), t.TempDir()
	engine := NewEngine(work, slog.New(slog.NewTextHandler(io.Discard, nil)))
	engine.SetYARA(client)
	command := func(path string) *pb.CmdVirusScan {
		return &pb.CmdVirusScan{TaskId: "native-yara", Mode: pb.CmdVirusScan_CUSTOM, Paths: []string{path}, Engine: "yara", ExecutionContract: 4, ExpectedDbVersion: version}
	}
	checks := []string{"no-builtin-library-required", "pinned-native-version-and-rule-source"}
	for _, sample := range []struct {
		name string
		data []byte
		hit  bool
	}{
		{"clean.txt", []byte("ordinary harmless content"), false},
		{"marker.txt", []byte(yaratest.Marker), true},
		{"tail.bin", append(append([]byte("MZ"), bytes.Repeat([]byte("_"), 3<<20)...), []byte(yaratest.Marker)...), true},
	} {
		path := filepath.Join(root, sample.name)
		if err := os.WriteFile(path, sample.data, 0600); err != nil {
			t.Fatal(err)
		}
		r := engine.ScanCommand(context.Background(), command(path), work)
		if r.Status != pb.RptVirusResult_COMPLETE || r.FilesScanned != 1 || len(r.Findings) != boolCount(sample.hit) || r.ExecutionContract != 4 {
			t.Fatalf("%s: %+v", sample.name, r)
		}
		if sample.hit {
			f := r.Findings[0]
			if f.Engine != "yara" || f.EngineVersion != version || f.Name != "AlinkSec_Native_Marker" || len(f.MatchedRules) != 2 || f.ActionTaken != "quarantined" {
				t.Fatal(f)
			}
			if err := NewQuarantine(work).RestoreExpected(context.Background(), path, f.QuarantineId, f.Sha256); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(b, sample.data) {
				t.Fatal("restore changed bytes", err)
			}
		}
		checks = append(checks, sample.name+"-native-scan-and-byte-bound-restore")
	}
	path := filepath.Join(root, "changed-rule.txt")
	os.WriteFile(path, []byte(yaratest.Marker), 0600)
	if err := os.WriteFile(cfg.RulesFile, []byte("rule Changed {condition:true}"), 0600); err != nil {
		t.Fatal(err)
	}
	r := engine.ScanCommand(context.Background(), command(path), work)
	if r.Status != pb.RptVirusResult_FAILED || len(r.Findings) != 0 || !strings.Contains(r.String(), "yara_rules_changed") {
		t.Fatal(r)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("failed native scan quarantined file", err)
	}
	if f := engine.CheckRealtime(path, work); f != nil {
		t.Fatal("failed engine generated realtime finding", f)
	}
	checks = append(checks, "changed-rules-refuse-task-and-realtime-quarantine")
	os.WriteFile(cfg.RulesFile, []byte(yaratest.Rules), 0600)
	if f := engine.CheckRealtime(path, work); f == nil || f.Engine != "yara" || len(f.MatchedRules) != 2 || f.ActionTaken != "quarantined" {
		t.Fatal("realtime", f, client.Status())
	}
	checks = append(checks, "realtime-recovers-and-quarantines-with-matched-rule-ids")
	large := filepath.Join(root, "large.bin")
	f, err := os.Create(large)
	if err != nil {
		t.Fatal(err)
	}
	err = f.Truncate(yara.MaxFileBytes + 1)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	r = engine.ScanCommand(context.Background(), command(large), work)
	if r.Status != pb.RptVirusResult_FAILED || r.FilesFailed != 1 || len(r.Findings) != 0 || !strings.Contains(r.String(), "yara_file_limit") {
		t.Fatal(r)
	}
	checks = append(checks, "oversize-is-failure-without-partial-action")
	if dest := os.Getenv("ALINKSEC_YARA_EVIDENCE_FILE"); dest != "" {
		b, _ := json.MarshalIndent(map[string]any{"passed": true, "os": runtime.GOOS, "arch": runtime.GOARCH, "version": version, "checks": checks, "status": client.Status()}, "", "  ")
		if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dest, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNativeYARAPacedTailPreservesFullFinding(t *testing.T) {
	cfg, version := yaratest.Native(t)
	client := yara.New(cfg, configguard.ReadFile)
	work := t.TempDir()
	engine := NewEngine(work, quietLogger())
	engine.SetYARA(client)
	data := append([]byte("MZ"), bytes.Repeat([]byte("_"), (64<<10)-2-len(yaratest.Marker)/2)...)
	data = append(data, []byte(yaratest.Marker)...)
	path := filepath.Join(t.TempDir(), "tail-marker")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	charged := 0
	engine.SetIOBudget(func(_ context.Context, n int) error {
		charged += n
		if charged > len(data)+1 {
			return context.DeadlineExceeded
		}
		return nil
	})
	f := engine.CheckFile(path, work, false)
	if f == nil || f.Engine != "yara" || f.EngineVersion != version || f.Name != "AlinkSec_Native_Marker" || len(f.MatchedRules) != 2 || f.Size != uint64(len(data)) || f.ActionTaken != "alert_only" || charged != len(data)+1 {
		t.Fatalf("paced full input failed: finding=%v charged=%d status=%+v", f, charged, client.Status())
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, data) {
		t.Fatal("alert changed file", err)
	}
}

func TestNativeRealtimeFailureDiagnostics(t *testing.T) {
	cfg, _ := yaratest.Native(t)
	work, root := t.TempDir(), t.TempDir()
	for _, sample := range []struct{ name, reason string }{
		{"missing", "file_missing"}, {"oversize", "file_limit"}, {"changing", "file_changed"}, {"paced", "timeout"},
	} {
		t.Run(sample.name, func(t *testing.T) {
			var logs bytes.Buffer
			e := NewEngine(work, slog.New(slog.NewJSONHandler(&logs, nil)))
			c := yara.New(cfg, configguard.ReadFile)
			e.SetYARA(c)
			path := filepath.Join(root, sample.name)
			if sample.name != "missing" {
				if err := os.WriteFile(path, []byte("harmless"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if sample.name == "oversize" {
				if err := os.Truncate(path, yara.MaxFileBytes+1); err != nil {
					t.Fatal(err)
				}
			}
			if sample.name == "changing" {
				e.SetIOBudget(func(context.Context, int) error {
					return os.WriteFile(path, []byte("harmless modified bytes"), 0600)
				})
			}
			if sample.name == "paced" {
				e.SetIOBudget(func(ctx context.Context, _ int) error { <-ctx.Done(); return ctx.Err() })
			}
			started := time.Now()
			if f := e.CheckFile(path, work, false); f != nil {
				t.Fatal("failed scan produced finding", f)
			}
			if time.Since(started) > 3*time.Second {
				t.Fatal("realtime deadline exceeded")
			}
			var entry map[string]any
			if json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &entry) != nil || entry["reason"] != sample.reason || entry["phase"] != "input" || entry["engine"] != "yara" || entry["path"] != path {
				t.Fatalf("missing diagnostic: %s", logs.String())
			}
			status := c.Status()
			if status.Failures != 1 || status.Scans != 1 || len(status.ScanFailures.Counts) != 1 {
				t.Fatal("diagnostics changed failure accounting", status)
			}
			if sample.name == "oversize" && (entry["bytes_read"] != float64(0) || entry["size_bytes"] != float64(yara.MaxFileBytes+1)) {
				t.Fatal("oversize diagnostic lost file metadata", entry)
			}
			if sample.name == "paced" {
				data, err := os.ReadFile(path)
				if err != nil || string(data) != "harmless" {
					t.Fatal("failed scan changed file", err)
				}
			}
		})
	}
}

func TestNativeRealtimeEngineFailurePhases(t *testing.T) {
	_, _ = yaratest.Native(t)
	for _, sample := range []struct{ name, rules, phase, reason string }{
		{"compile", `rule broken {condition:}`, "probe", "yara_compile_error"},
		{"worker-timeout", `rule expensive {condition: for all i in (0..1000000000) : (uint8(i % filesize)==65)}`, "scan", "yara_timeout"},
	} {
		t.Run(sample.name, func(t *testing.T) {
			var logs bytes.Buffer
			work, root := t.TempDir(), t.TempDir()
			e := NewEngine(work, slog.New(slog.NewJSONHandler(&logs, nil)))
			e.SetYARA(yara.New(yaratest.Config(t, sample.rules), configguard.ReadFile))
			path := filepath.Join(root, "harmless")
			data := bytes.Repeat([]byte("A"), 1024)
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			if finding := e.CheckFile(path, work, true); finding != nil {
				t.Fatal("failed engine produced finding", finding)
			}
			var entry map[string]any
			if json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &entry) != nil || entry["phase"] != sample.phase || entry["reason"] != sample.reason {
				t.Fatalf("wrong failure phase: %s", logs.String())
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, data) || time.Since(started) > 3*time.Second {
				t.Fatal("failed engine changed file or exceeded realtime deadline", err)
			}
		})
	}
}
