package guard

import (
	"github.com/alinksec/alinksec-agent/internal/config"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRecoveryVirusProtectionIndependentOfDecoyAndReportsIdentity(t *testing.T) {
	root := t.TempDir()
	enabled := true
	checks := 0
	var events []*pb.RptSecurityEvent
	disabled := false
	g := New(&config.DecoyConfig{Enabled: &disabled}, nil, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)), func(e *pb.RptSecurityEvent) { events = append(events, e) })
	g.SetVirusRoots([]string{root}, func() bool { return enabled })
	g.SetVirusEngine(func(path string) *pb.VirusFinding {
		checks++
		return &pb.VirusFinding{Path: path, Name: "Harmless", Engine: "hash", Sha256: "digest", Severity: pb.Severity_SEV_HIGH, ActionTaken: "alert_only", ActionError: "budget_exhausted"}
	})
	g.virusRescan = true
	g.fileEventLoop()
	path := filepath.Join(root, "new.sh")
	os.WriteFile(path, []byte("harmless"), 0600)
	g.virusRescan = true
	g.fileEventLoop()
	if checks != 1 || len(events) != 1 || events[0].Severity != pb.Severity_SEV_HIGH || events[0].Type != "virus" {
		t.Fatal(checks, events)
	}
	g.fileEventLoop()
	if checks != 1 {
		t.Fatal("unchanged file rescanned")
	}
	enabled = false
	os.WriteFile(path, []byte("changed harmless"), 0600)
	g.virusRescan = true
	g.fileEventLoop()
	if checks != 1 {
		t.Fatal("disabled policy checked file")
	}
	enabled = true
	g.fileEventLoop()
	if checks != 2 {
		t.Fatal("reenabled policy missed changes")
	}
}
func TestPeriodicSnapshotBoundsDirectoriesAndUsesNanosecondTime(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 10; i++ {
		os.Mkdir(filepath.Join(root, string(rune('a'+i))), 0700)
	}
	left := 3
	virusSnapshot(root, &left, time.Now().Add(time.Second))
	if left != 0 {
		t.Fatal("directory entries not bounded", left)
	}
	left = 100
	path := filepath.Join(root, "same.sh")
	os.WriteFile(path, []byte("old"), 0600)
	stamp := time.Unix(100, 100)
	os.Chtimes(path, stamp, stamp)
	first := virusSnapshot(root, &left, time.Now().Add(time.Second))
	stamp = time.Unix(100, 500000)
	os.Chtimes(path, stamp, stamp)
	left = 100
	next := virusSnapshot(root, &left, time.Now().Add(time.Second))
	if len(diffSnapshot(first, next).Modified) != 1 {
		t.Fatal("sub-second modification missed")
	}
}
