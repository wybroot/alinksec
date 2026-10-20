package virusscan

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/alinksec/alinksec-agent/internal/clamav"
	"github.com/alinksec/alinksec-agent/internal/clamav/clamavtest"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func TestNativeClamavScan(t *testing.T) {
	cfg, version := clamavtest.Native(t)
	client := clamav.New(cfg)
	work, root := t.TempDir(), t.TempDir()
	engine := NewEngine(work, slog.New(slog.NewTextHandler(io.Discard, nil)))
	engine.SetClamAV(client)
	checks := []string{"real-clamd-1.4.6-private-custom-database", "pinned-tls-instream"}
	zipData := func(data []byte) []byte {
		var b bytes.Buffer
		w := zip.NewWriter(&b)
		f, err := w.Create("content.txt")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write(data); err != nil {
			t.Fatal(err)
		}
		if err = w.Close(); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	for _, sample := range []struct {
		name    string
		data    []byte
		finding bool
	}{
		{"clean.txt", []byte("ordinary harmless content"), false},
		{"marker.txt", []byte(clamavtest.Marker), true},
		{"archive.zip", zipData([]byte(clamavtest.Marker)), true},
	} {
		path := filepath.Join(root, sample.name)
		if err := os.WriteFile(path, sample.data, 0600); err != nil {
			t.Fatal(err)
		}
		cmd := clamCommand(path)
		cmd.ExpectedDbVersion = version
		r := engine.ScanCommand(context.Background(), cmd, work)
		if r.Status != pb.RptVirusResult_COMPLETE || r.FilesScanned != 1 || len(r.Findings) != boolCount(sample.finding) {
			t.Fatalf("%s result=%+v", sample.name, r)
		}
		if sample.finding {
			f := r.Findings[0]
			if !strings.Contains(f.Name, "AlinkSec.Harmless.Marker") || f.Engine != "clamav" || f.EngineVersion != version || f.ActionTaken != "quarantined" {
				t.Fatal(f)
			}
			if err := NewQuarantine(work).RestoreExpected(context.Background(), path, f.QuarantineId, f.Sha256); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(b, sample.data) {
				t.Fatalf("restored bytes changed: %v", err)
			}
		}
		checks = append(checks, sample.name+"-scan-and-byte-bound-action")
	}
	large := filepath.Join(root, "expansion-limit.zip")
	if err := os.WriteFile(large, zipData(bytes.Repeat([]byte("harmless expanded bytes\n"), 100000)), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := clamCommand(large)
	cmd.ExpectedDbVersion = version
	r := engine.ScanCommand(context.Background(), cmd, work)
	if r.Status != pb.RptVirusResult_FAILED || len(r.Findings) != 0 || r.FilesFailed != 1 || !strings.Contains(r.String(), "clamav_incomplete") {
		t.Fatalf("native limit must not quarantine: %+v", r)
	}
	if _, err := os.Stat(large); err != nil {
		t.Fatal(err)
	}
	checks = append(checks, "real-archive-limit-refuses-quarantine")
	path := filepath.Join(root, "realtime.txt")
	os.WriteFile(path, []byte(clamavtest.Marker), 0600)
	if f := engine.CheckRealtime(path, work); f == nil || f.Engine != "clamav" || f.ActionTaken != "quarantined" {
		t.Fatalf("native realtime=%+v status=%+v", f, client.Status())
	}
	checks = append(checks, "real-realtime-engine-quarantine")
	if dest := os.Getenv("ALINKSEC_CLAMAV_EVIDENCE_FILE"); dest != "" {
		data, _ := json.MarshalIndent(map[string]any{"passed": true, "os": runtime.GOOS, "arch": runtime.GOARCH, "version": version, "checks": checks, "status": client.Status(), "database": "private harmless custom NDB; no full official definitions or update/performance certification"}, "", "  ")
		if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dest, append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
func boolCount(v bool) int {
	if v {
		return 1
	}
	return 0
}
