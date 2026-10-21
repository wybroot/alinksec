package virusscan

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func TestNativeSignatureDelta(t *testing.T) {
	dir := os.Getenv("ALINKSEC_SIGNATURE_FIXTURE_DIR")
	if dir == "" {
		t.Skip("requires independently produced release fixtures")
	}
	var release struct {
		Producer    string `json:"producer"`
		Version     string `json:"version"`
		SHA256      string `json:"sha256"`
		DeltaSHA256 string `json:"delta_sha256"`
		BaseVersion string `json:"base_version"`
		BaseContent string `json:"base_content_sha256"`
		Content     string `json:"content_sha256"`
		BaseSHA256  string `json:"base_sha256"`
	}
	read := func(name string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if err := json.Unmarshal(read("release.json"), &release); err != nil {
		t.Fatal(err)
	}
	base, full, delta := read("base.zip"), read("target.zip"), read("delta.zip")
	if digestBytes(base) != release.BaseSHA256 || digestBytes(full) != release.SHA256 || digestBytes(delta) != release.DeltaSHA256 || len(delta) >= len(full) {
		t.Fatal("fixture archive identity or size invalid")
	}
	work := t.TempDir()
	installFixture(t, work, base)
	engine := NewEngine(work, slog.New(slog.NewTextHandler(io.Discard, nil)))
	marker := filepath.Join(t.TempDir(), "增量更新样本 with spaces.txt")
	if err := os.WriteFile(marker, []byte("new-harmless-entry"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := engine.Scan("before", pb.CmdVirusScan_CUSTOM, []string{marker}, work); got.Status != pb.RptVirusResult_COMPLETE || len(got.Findings) != 0 {
		t.Fatal("base incorrectly detects newly added marker", got)
	}
	var mu sync.Mutex
	corrupt := false
	paths := []string{}
	server := signatureServer(t, work, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/delta" {
			if corrupt {
				w.Write([]byte("damaged"))
			} else {
				w.Write(delta)
			}
		} else {
			w.Write(full)
		}
	})
	spec := UpdateSpec{Version: release.Version, URL: server.URL + "/full", SHA256: release.SHA256, DeltaURL: server.URL + "/delta", DeltaSHA256: release.DeltaSHA256, BaseVersion: release.BaseVersion, BaseContent: release.BaseContent, Content: release.Content}
	receipt, err := UpdateRelease(context.Background(), work, spec)
	if err != nil || receipt.Mode != "delta" || receipt.Downloaded != int64(len(delta)) {
		t.Fatal(receipt, err)
	}
	digest, err := contentDigest(DBDir(work))
	if err != nil || digest != release.Content {
		t.Fatal("reconstructed bytes differ", digest, err)
	}
	if finding := engine.CheckAndQuarantine(marker, work); finding == nil || finding.Name != "Added.Fixture" || finding.ActionTaken != "quarantined" {
		t.Fatal("live engine retained obsolete clean state", finding)
	}
	current, err := UpdateRelease(context.Background(), work, spec)
	if err != nil || current.Mode != "already-current" || current.Downloaded != 0 {
		t.Fatal(current, err)
	}
	installFixture(t, work, base)
	mu.Lock()
	corrupt = true
	mu.Unlock()
	fallback, err := UpdateRelease(context.Background(), work, spec)
	if err != nil || fallback.Mode != "full" || fallback.Fallback != "delta-failed" {
		t.Fatal(fallback, err)
	}
	installFixture(t, work, base)
	if err := os.WriteFile(filepath.Join(DBDir(work), "hashes.txt"), []byte(strings.Repeat("f", 64)+" Different 3\n"), 0600); err != nil {
		t.Fatal(err)
	}
	mismatch, err := UpdateRelease(context.Background(), work, spec)
	if err != nil || mismatch.Mode != "full" || mismatch.Fallback != "base-mismatch" {
		t.Fatal(mismatch, err)
	}
	installFixture(t, work, base)
	bad := spec
	bad.Content = strings.Repeat("0", 64)
	if _, err := UpdateRelease(context.Background(), work, bad); err == nil || LocalVersion(work) != release.BaseVersion {
		t.Fatal("failed target displaced old library", err)
	}
	if err := os.Rename(DBDir(work), DBDir(work)+".old"); err != nil {
		t.Fatal(err)
	}
	if !ReloadDB(work).Valid || LocalVersion(work) != release.BaseVersion {
		t.Fatal("native interrupted switch recovery failed")
	}
	if dest := os.Getenv("ALINKSEC_SIGNATURE_EVIDENCE_FILE"); dest != "" {
		mu.Lock()
		captured := append([]string(nil), paths...)
		mu.Unlock()
		data, _ := json.MarshalIndent(map[string]any{"passed": true, "os": runtime.GOOS, "arch": runtime.GOARCH, "producer": release.Producer, "base_version": release.BaseVersion, "version": release.Version, "content_sha256": release.Content, "base_sha256": release.BaseSHA256, "delta_sha256": release.DeltaSHA256, "sha256": release.SHA256, "full_bytes": len(full), "delta_bytes": len(delta), "receipt": receipt, "fallback": fallback, "base_mismatch": mismatch, "paths": captured, "checks": []string{"independent-producer-content-and-package-identities", "native-tls-delta-download-only", "exact-reconstructed-target-bytes", "live-engine-new-hash-quarantine-without-stale-clean-cache", "idempotent-replay-without-download", "bad-delta-full-fallback", "base-mismatch-full-fallback", "invalid-target-preserves-old-library", "native-interrupted-switch-recovery"}}, "", "  ")
		if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dest, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
