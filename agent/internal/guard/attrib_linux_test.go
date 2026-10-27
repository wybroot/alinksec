//go:build linux

package guard

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/config"
	"github.com/alinksec/alinksec-agent/internal/filetrace"
)

// This helper only holds a fixture descriptor and waits for its parent's EOF.
func TestLinuxAttributionHelper(t *testing.T) {
	role := os.Getenv("ALINKSEC_ATTRIBUTION_HELPER")
	if role == "" {
		t.Skip("child fixture")
	}
	if role != "idle" {
		flags := os.O_RDONLY
		if role == "writer" {
			flags = os.O_RDWR
		}
		f, err := os.OpenFile(os.Getenv("ALINKSEC_ATTRIBUTION_PATH"), flags, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if role == "writer" {
			if _, err := f.WriteAt([]byte("harmless change"), 0); err != nil {
				t.Fatal(err)
			}
			if err := f.Sync(); err != nil {
				t.Fatal(err)
			}
		}
	}
	fmt.Println("ready")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		fmt.Println("alive")
	}
}

func TestLinuxRansomResponseDoesNotGuessWriter(t *testing.T) {
	for _, role := range []string{"idle", "reader", "neighbor_reader", "writer"} {
		t.Run(role, func(t *testing.T) {
			root := t.TempDir()
			enabled := true
			cfg := &config.DecoyConfig{Enabled: &enabled, Dirs: []string{root}, CountPerDir: 1, Response: "kill"}
			cfg.Normalize()
			g := New(cfg, nil, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
			g.initialDeploy()
			decoys := newDecoyManager(cfg, g.workDir).knownDecoys()
			if len(decoys) != 1 {
				t.Fatalf("deployed %d decoys", len(decoys))
			}
			path := decoys[0]
			helperPath := path
			if role == "neighbor_reader" {
				helperPath = filepath.Join(root, "unrelated.txt")
				if err := os.WriteFile(helperPath, []byte("unrelated business file"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestLinuxAttributionHelper$")
			cmd.Env = append(os.Environ(), "ALINKSEC_ATTRIBUTION_HELPER="+role, "ALINKSEC_ATTRIBUTION_PATH="+helperPath)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { stdin.Close(); cancel(); _ = cmd.Wait() }()
			reader := bufio.NewReader(stdout)
			if line, err := reader.ReadString('\n'); err != nil || line != "ready\n" {
				t.Fatalf("helper not ready: %q, %v", line, err)
			}
			if err := os.WriteFile(path, []byte("harmless tampering"), 0600); err != nil {
				t.Fatal(err)
			}

			// Check attribution before invoking any response, so a regression
			// cannot make this test terminate an unrelated host process.
			detail := map[string]any{}
			proc, terminate := g.attributeResponse([]string{path}, time.Now().Add(-time.Second), detail)
			if proc != nil {
				t.Fatalf("selected an unverified process: pid=%d", proc.Pid)
			}
			if err := terminate(); err == nil {
				t.Fatal("termination without writer evidence was accepted")
			}
			attribution, ok := detail["attribution"].(filetrace.Result)
			if !ok || attribution.Status != "unavailable" || attribution.Reason != "linux_writer_capture_unavailable" || attribution.Process != nil {
				t.Fatalf("missing coverage limitation: %+v", detail)
			}
			for _, trigger := range []string{"decoy_tampered", "ransom_rate"} {
				ruleID, ruleName := ruleDecoyID, ruleDecoyName
				if trigger == "ransom_rate" {
					ruleID, ruleName = ruleRateID, ruleRateName
				}
				event := g.respondSince(trigger, ruleID, ruleName, []string{path}, []string{path}, time.Now().Add(-time.Second))
				var evidence map[string]any
				if err := json.Unmarshal([]byte(event.Detail), &evidence); err != nil {
					t.Fatal(err)
				}
				if event.ActionTaken != "alert_only" || len(event.EvidenceKeys) == 0 || evidence["kill_error"] == nil || evidence["process"] != nil {
					t.Fatalf("response claimed termination or lost evidence: %+v", event)
				}
				if _, err := io.WriteString(stdin, "ping\n"); err != nil {
					t.Fatalf("fixture was terminated: %v", err)
				}
				if line, err := reader.ReadString('\n'); err != nil || line != "alive\n" {
					t.Fatalf("fixture no longer responds: %q, %v", line, err)
				}
			}
		})
	}
}
