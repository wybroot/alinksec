package virusscan

import (
	"context"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/alinksec/alinksec-agent/internal/configguard"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/yara"
	"github.com/alinksec/alinksec-agent/internal/yara/yaratest"
)

func TestNativeYARAUpdatedSourceDrivesFileDetection(t *testing.T) {
	_, _ = yaratest.Native(t)
	var mu sync.Mutex
	rules := `rule Old { strings: $s="harmless old signature" condition: $s }`
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_, _ = io.WriteString(w, rules)
	}))
	defer server.Close()
	work, root := t.TempDir(), t.TempDir()
	ca := filepath.Join(root, "publisher-ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	client := yara.NewWithUpdates(yara.Config{Enabled: true, UpdateURL: server.URL + "/approved.yar", UpdateCAFile: ca}, configguard.ReadFile, work)
	if err := client.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(work, slog.New(slog.NewTextHandler(io.Discard, nil)))
	engine.SetYARA(client)
	path := filepath.Join(root, "new-marker.txt")
	content := []byte("a harmless new signature for the update integration check")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	command := &pb.CmdVirusScan{TaskId: "updated-yara", Mode: pb.CmdVirusScan_CUSTOM, Paths: []string{path}, Engine: "yara", ExecutionContract: 4, ExpectedDbVersion: client.Status().Version}
	first := engine.ScanCommand(context.Background(), command, work)
	if first.Status != pb.RptVirusResult_COMPLETE || len(first.Findings) != 0 {
		t.Fatal(first)
	}
	mu.Lock()
	rules = `rule NewlyPublished { strings: $s="harmless new signature" condition: $s }`
	mu.Unlock()
	if err := client.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	old := engine.ScanCommand(context.Background(), command, work)
	if old.Status != pb.RptVirusResult_FAILED || len(old.Findings) != 0 {
		t.Fatal("old task accepted replaced rules", old)
	}
	command.ExpectedDbVersion = client.Status().Version
	updated := engine.ScanCommand(context.Background(), command, work)
	if updated.Status != pb.RptVirusResult_COMPLETE || len(updated.Findings) != 1 {
		t.Fatal(updated)
	}
	f := updated.Findings[0]
	if f.Name != "NewlyPublished" || f.EngineVersion != command.ExpectedDbVersion || f.ActionTaken != "quarantined" {
		t.Fatal(f)
	}
	if err := NewQuarantine(work).RestoreExpected(context.Background(), path, f.QuarantineId, f.Sha256); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	rules = "rule broken {condition:}"
	mu.Unlock()
	if err := client.Refresh(context.Background()); err == nil {
		t.Fatal("invalid new rules accepted")
	}
	retained := engine.ScanCommand(context.Background(), command, work)
	if retained.Status != pb.RptVirusResult_COMPLETE || len(retained.Findings) != 1 || retained.Findings[0].Name != "NewlyPublished" {
		t.Fatal("last working rules lost", retained)
	}
}
