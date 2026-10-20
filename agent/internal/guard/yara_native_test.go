//go:build linux || windows

package guard

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/config"
	"github.com/alinksec/alinksec-agent/internal/configguard"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/virusscan"
	"github.com/alinksec/alinksec-agent/internal/yara"
	"github.com/alinksec/alinksec-agent/internal/yara/yaratest"
)

func TestNativeYARAFileEvent(t *testing.T) {
	cfg, version := yaratest.Native(t)
	disabled := false
	root := t.TempDir()
	var reports []*pb.RptSecurityEvent
	g := New(&config.DecoyConfig{Enabled: &disabled}, nil, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)), func(e *pb.RptSecurityEvent) { reports = append(reports, e) })
	engine := virusscan.NewEngine(g.workDir, g.log)
	engine.SetYARA(yara.New(cfg, configguard.ReadFile))
	g.SetVirusRoots([]string{root}, func() bool { return true })
	g.SetVirusEngine(func(p string) *pb.VirusFinding { return engine.CheckRealtime(p, g.workDir) })
	g.updateFileWatches()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { g.watcher.Run(ctx); close(done) }()
	defer func() {
		cancel()
		<-done
		if g.virusRecovery != nil {
			g.virusRecovery.Close()
		}
	}()
	wait := func(predicate func() bool) {
		t.Helper()
		end := time.Now().Add(12 * time.Second)
		for time.Now().Before(end) {
			g.updateFileWatches()
			g.fileEventLoop()
			if predicate() {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("native YARA event timeout status=%s reports=%v", g.FileWatchStatus(), reports)
	}
	wait(func() bool { return g.watcher.Status().Watches > 0 })
	path := filepath.Join(root, "native-yara-marker.txt")
	if err := os.WriteFile(path, []byte(yaratest.Marker), 0600); err != nil {
		t.Fatal(err)
	}
	wait(func() bool { return len(reports) > 0 })
	var observed map[string]any
	for _, r := range reports {
		if r.Type == "virus" {
			if err := json.Unmarshal([]byte(r.Detail), &observed); err != nil {
				t.Fatal(err)
			}
		}
	}
	if observed["engine"] != "yara" || observed["engine_version"] != version || observed["action"] != "quarantined" || observed["path"] != path {
		t.Fatalf("event=%v", observed)
	}
	if ids, ok := observed["matched_rules"].([]any); !ok || len(ids) != 2 || ids[0] != "AlinkSec_Native_Marker" {
		t.Fatalf("matched rule evidence=%v", observed)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("event fixture not quarantined: %v", err)
	}
	if dest := os.Getenv("ALINKSEC_YARA_EVENT_EVIDENCE_FILE"); dest != "" {
		data, _ := json.MarshalIndent(map[string]any{"passed": true, "os": runtime.GOOS, "arch": runtime.GOARCH, "version": version, "checks": []string{"native-file-event", "native-libyara-worker", "byte-bound-quarantine", "guard-event-with-engine-version"}, "event": observed}, "", "  ")
		if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dest, append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
