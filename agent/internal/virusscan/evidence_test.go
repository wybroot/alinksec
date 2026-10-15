package virusscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func harmlessSample(t *testing.T, data string) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "harmless.sh")
	if err := os.WriteFile(path, []byte(data), 0750); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(data))
	return path, hex.EncodeToString(sum[:])
}
func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
func TestContentChangedWithPreservedMetadataMustBeScanned(t *testing.T) {
	work := t.TempDir()
	path, bad := harmlessSample(t, "BAD")
	testDB(t, work, "bytes", bad)
	os.WriteFile(path, []byte("OK!"), 0750)
	before, _ := os.Stat(path)
	engine := NewEngine(work, quietLogger())
	if r := engine.Scan("first", pb.CmdVirusScan_CUSTOM, []string{path}, work); len(r.GetFindings()) != 0 || r.GetStatus() != pb.RptVirusResult_COMPLETE {
		t.Fatal(r)
	}
	os.WriteFile(path, []byte("BAD"), 0750)
	os.Chtimes(path, before.ModTime(), before.ModTime())
	r := engine.Scan("second", pb.CmdVirusScan_CUSTOM, []string{path}, work)
	if len(r.Findings) != 1 || r.Findings[0].Sha256 != bad || r.Findings[0].QuarantineId == "" {
		t.Fatalf("metadata bypassed current bytes: %v", r)
	}
}
func TestScanFailuresAndBudgetsNeverClaimCompletion(t *testing.T) {
	work := t.TempDir()
	path, hash := harmlessSample(t, "harmless")
	testDB(t, work, "budget", strings.Repeat("0", 64))
	engine := NewEngine(work, quietLogger())
	missing := filepath.Join(t.TempDir(), "missing")
	r := engine.Scan("partial", pb.CmdVirusScan_CUSTOM, []string{path, missing}, work)
	if r.Status != pb.RptVirusResult_PARTIAL || r.FilesScanned != 1 || r.FilesFailed != 1 {
		t.Fatal(r)
	}
	r = engine.ScanCommand(context.Background(), &pb.CmdVirusScan{ExecutionContract: 2, TaskId: "limited", Mode: pb.CmdVirusScan_CUSTOM, Paths: []string{path}, MaxTotalBytes: 1}, work)
	if r.Status != pb.RptVirusResult_FAILED || !r.BudgetExhausted || r.FilesScanned != 0 {
		t.Fatal(r)
	}
	r = engine.ScanCommand(context.Background(), &pb.CmdVirusScan{ExecutionContract: 2, Mode: pb.CmdVirusScan_CUSTOM, Paths: []string{path}, ExpectedDbVersion: "other"}, work)
	if r.Status != pb.RptVirusResult_FAILED || r.FilesScanned != 0 {
		t.Fatal(r)
	}
	testDB(t, work, "empty", hash)
	empty := filepath.Join(t.TempDir(), "empty")
	os.Mkdir(empty, 0700)
	if r = engine.Scan("empty-scope", pb.CmdVirusScan_CUSTOM, []string{empty}, work); r.Status != pb.RptVirusResult_COMPLETE || r.FilesScanned != 0 {
		t.Fatal(r)
	}
	if !strings.Contains(r.Coverage, "2MiB") || !strings.Contains(r.Coverage, "archives not expanded") {
		t.Fatal("coverage not disclosed")
	}
}
func TestQuarantineDeleteCannotRemoveReplacementAtOriginalPath(t *testing.T) {
	work := t.TempDir()
	path, hash := harmlessSample(t, "old harmless sample")
	q := NewQuarantine(work)
	id, err := q.QuarantineExpected(context.Background(), path, hash)
	if err != nil {
		t.Fatal(err)
	}
	replacement := []byte("new unrelated file")
	os.WriteFile(path, replacement, 0600)
	if err = q.RestoreExpected(context.Background(), path, id, hash); err == nil {
		t.Fatal("restore overwrote replacement")
	}
	if err = q.DeleteExpected(context.Background(), path, id, hash); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(replacement) {
		t.Fatal("delete affected new file")
	}
}
func TestDigestAndMetadataTamperingRejectDestructiveActions(t *testing.T) {
	work := t.TempDir()
	path, hash := harmlessSample(t, "harmless expected bytes")
	q := NewQuarantine(work)
	if _, err := q.QuarantineExpected(context.Background(), path, strings.Repeat("a", 64)); err == nil {
		t.Fatal("different bytes accepted")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("mismatched original was moved")
	}
	id, err := q.QuarantineExpected(context.Background(), path, hash)
	if err != nil {
		t.Fatal(err)
	}
	payload := filepath.Join(q.dir, id+".payload")
	os.Chmod(payload, 0600)
	os.WriteFile(payload, []byte("changed"), 0600)
	if err = q.RestoreExpected(context.Background(), path, id, hash); err == nil {
		t.Fatal("changed quarantine restored")
	}
	if err = q.DeleteExpected(context.Background(), path, id, hash); err == nil {
		t.Fatal("changed quarantine destroyed")
	}
	if _, err = os.Stat(payload); err != nil {
		t.Fatal("unverified bytes removed")
	}
	if err = q.Delete(path); err == nil {
		t.Fatal("legacy path-only deletion accepted")
	}
}
func TestRestorePreservesPermissionsAndRejectsChangedParent(t *testing.T) {
	work := t.TempDir()
	path, hash := harmlessSample(t, "restore harmless test")
	q := NewQuarantine(work)
	before, _ := os.Stat(path)
	id, err := q.QuarantineExpected(context.Background(), path, hash)
	if err != nil {
		t.Fatal(err)
	}
	if err = q.RestoreExpected(context.Background(), path, id, hash); err != nil {
		t.Fatal(err)
	}
	restored, _ := os.Stat(path)
	if restored.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf("permission drift: %v -> %v", before.Mode(), restored.Mode())
	}
	id, err = q.QuarantineExpected(context.Background(), path, hash)
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Dir(path)
	moved := parent + "-moved"
	if err = os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	defer os.Rename(moved, parent)
	os.Mkdir(parent, 0700)
	defer os.Remove(parent)
	if err = q.RestoreExpected(context.Background(), path, id, hash); err == nil {
		t.Fatal("restored into substituted parent")
	}
}
func TestCancelledQuarantineWaitIsBounded(t *testing.T) {
	quarantineGate <- struct{}{}
	defer func() { <-quarantineGate }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := NewQuarantine(t.TempDir()).QuarantineExpected(ctx, "/missing", strings.Repeat("0", 64)); err == nil {
		t.Fatal("cancelled wait succeeded")
	}
}
func TestProtectedWorkDirectoryCannotBeScannedOrMutated(t *testing.T) {
	work := t.TempDir()
	path := filepath.Join(work, "private.key")
	os.WriteFile(path, []byte("private harmless test"), 0600)
	sum := sha256.Sum256([]byte("private harmless test"))
	hash := hex.EncodeToString(sum[:])
	testDB(t, work, "self", hash)
	r := NewEngine(work, quietLogger()).Scan("self", pb.CmdVirusScan_CUSTOM, []string{path}, work)
	if r.FilesScanned != 0 || len(r.Findings) != 0 || r.FilesSkipped != 1 {
		t.Fatal(r)
	}
	if _, err := NewQuarantine(work).QuarantineExpected(context.Background(), path, hash); err == nil {
		t.Fatal("Agent state could be quarantined")
	}
}
