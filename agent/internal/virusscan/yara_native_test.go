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
