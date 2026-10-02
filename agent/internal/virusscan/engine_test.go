package virusscan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func testDB(t *testing.T, dir, version, hash string) {
	t.Helper()
	if err := os.MkdirAll(DBDir(dir), 0700); err != nil {
		t.Fatal(err)
	}
	manifest, _ := json.Marshal(dbManifest{DbVersion: version, HashCount: 1})
	for path, data := range map[string][]byte{
		"manifest.json": manifest,
		"hashes.txt":    []byte(hash + " Test.Harmless 3\n"),
	} {
		if err := os.WriteFile(filepath.Join(DBDir(dir), path), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ReloadDB(dir)
}

func TestSignatureUpdateInvalidatesLiveAndPersistedCleanCaches(t *testing.T) {
	dir := t.TempDir()
	data := []byte("harmless signature update test")
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	testDB(t, dir, "v1", strings.Repeat("0", 64))
	liveFile, scanFile := filepath.Join(dir, "live.txt"), filepath.Join(dir, "scan.txt")
	for _, path := range []string{liveFile, scanFile} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := NewEngine(dir, log)
	if result := engine.Scan("clean", pb.CmdVirusScan_CUSTOM, []string{liveFile, scanFile}, dir); len(result.GetFindings()) != 0 {
		t.Fatal("v1 must treat test files as clean")
	}
	testDB(t, dir, "v2", hash)
	if finding := engine.CheckAndQuarantine(liveFile, dir); finding == nil || finding.GetActionTaken() != "quarantined" {
		t.Fatal("running realtime engine did not pick up new signature")
	}
	result := NewEngine(dir, log).Scan("updated", pb.CmdVirusScan_CUSTOM, []string{scanFile}, dir)
	if len(result.GetFindings()) != 1 {
		t.Fatal("new signature was bypassed by persisted clean cache")
	}
}

func TestWhitelistPreventsScanAndRealtimeQuarantineAndCanBeRemoved(t *testing.T) {
	for _, mode := range []string{"scan", "realtime"} {
		for _, kind := range []string{"hash", "path"} {
			t.Run(mode+"/"+kind, func(t *testing.T) {
				dir := t.TempDir()
				file := filepath.Join(dir, "harmless.txt")
				data := []byte("harmless whitelist test")
				sum := sha256.Sum256(data)
				hash := hex.EncodeToString(sum[:])
				testDB(t, dir, "v1", hash)
				if err := os.WriteFile(file, data, 0600); err != nil {
					t.Fatal(err)
				}
				value := hash
				if kind == "path" {
					value = dir
				}
				policy, _ := json.Marshal(map[string]any{"virus_whitelist": []whitelistEntry{{Type: kind, Value: value}}})
				if err := os.WriteFile(filepath.Join(dir, "policy.json"), policy, 0600); err != nil {
					t.Fatal(err)
				}
				engine := NewEngine(dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
				check := func() bool {
					if mode == "scan" {
						return len(engine.Scan("test", pb.CmdVirusScan_CUSTOM, []string{file}, dir).GetFindings()) != 0
					}
					return engine.CheckAndQuarantine(file, dir) != nil
				}
				if check() {
					t.Fatal("whitelisted file detected")
				}
				if _, err := os.Stat(file); err != nil {
					t.Fatalf("whitelisted file was moved: %v", err)
				}
				if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(`{"virus_whitelist":[]}`), 0600); err != nil {
					t.Fatal(err)
				}
				if !check() {
					t.Fatal("removing whitelist did not restore protection")
				}
			})
		}
	}
}

func TestPathWhitelistDoesNotMatchSiblingPrefix(t *testing.T) {
	engine := &Engine{whitelist: []whitelistEntry{{Type: "path", Value: filepath.Join("root", "safe")}}}
	if engine.whitelisted(filepath.Join("root", "safe-other", "file"), "") {
		t.Fatal("directory whitelist matched sibling with shared prefix")
	}
	if !engine.whitelisted(filepath.Join("root", "safe", "file"), "") {
		t.Fatal("directory whitelist did not match child")
	}
}
