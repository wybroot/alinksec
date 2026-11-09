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
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/config"
)

// The helper owns only disposable test files and a disposable descendant.
// No production termination function is ever invoked with a candidate PID.
func TestLinuxAttributionHelper(t *testing.T) {
	mode := os.Getenv("ALINKSEC_LINUX_ATTRIB_HELPER")
	if mode == "" {
		return
	}
	flags := os.O_RDONLY
	if mode != "reader" {
		flags = os.O_RDWR | os.O_APPEND
	}
	f, err := os.OpenFile(os.Getenv("ALINKSEC_LINUX_ATTRIB_FILE"), flags, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if mode != "reader" {
		if _, err := f.WriteString("controlled test write\n"); err != nil {
			t.Fatal(err)
		}
	}
	if mode == "closed_writer" || mode == "exited_writer" {
		f.Close()
	}
	if mode == "exited_writer" {
		return
	}
	child := exec.Command("sleep", "30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	fmt.Println(child.Process.Pid)
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func startLinuxAttributionHelper(t *testing.T, mode, path string) (int, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLinuxAttributionHelper$")
	cmd.Env = append(os.Environ(), "ALINKSEC_LINUX_ATTRIB_HELPER="+mode, "ALINKSEC_LINUX_ATTRIB_FILE="+path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stdin.Close(); _ = cmd.Wait(); cancel() })
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		t.Fatal("helper did not report a ready descendant")
	}
	child, err := strconv.Atoi(strings.TrimSpace(scanner.Text()))
	if err != nil {
		t.Fatal(err)
	}
	return cmd.Process.Pid, child
}

func TestNativeLinuxRansomAttribution(t *testing.T) {
	for _, scenario := range []string{"readonly_target", "readonly_neighbor", "writable_neighbor", "closed_writer", "exited_writer", "multiple_writers", "missing_file", "no_files"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "decoy.txt")
			neighbor := filepath.Join(dir, "business.txt")
			for _, p := range []string{target, neighbor} {
				if err := os.WriteFile(p, []byte("test\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			// A recent unrelated process tree exists in every scenario.
			parent, child := startLinuxAttributionHelper(t, "reader", neighbor)
			pids := []int{parent, child}
			mode, path := "reader", target
			switch scenario {
			case "readonly_neighbor":
				path = neighbor
			case "writable_neighbor":
				mode, path = "writer", neighbor
			case "closed_writer":
				mode = "closed_writer"
			case "multiple_writers":
				mode = "writer"
			case "exited_writer":
				cmd := exec.Command(os.Args[0], "-test.run=^TestLinuxAttributionHelper$")
				cmd.Env = append(os.Environ(), "ALINKSEC_LINUX_ATTRIB_HELPER=exited_writer", "ALINKSEC_LINUX_ATTRIB_FILE="+target)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("writer: %v: %s", err, out)
				}
			}
			if scenario != "exited_writer" {
				parent, child = startLinuxAttributionHelper(t, mode, path)
				pids = append(pids, parent, child)
			}
			if scenario == "multiple_writers" {
				parent, child = startLinuxAttributionHelper(t, "writer", target)
				pids = append(pids, parent, child)
			}
			files := []string{target}
			if scenario == "missing_file" {
				files = []string{filepath.Join(dir, "gone")}
			}
			if scenario == "no_files" {
				files = nil
			}
			for _, response := range []string{"alert_only", "kill", "kill_and_isolate"} {
				cfg := &config.DecoyConfig{Response: response}
				g := &Guard{cfg: cfg, workDir: dir, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
				detail := map[string]any{}
				proc, terminate := g.attributeResponse(files, time.Now().Add(-time.Minute), detail)
				if proc != nil {
					t.Fatalf("selected unverified process: %+v", proc)
				}
				if terminate == nil || terminate() == nil {
					t.Fatal("unverified termination must be denied")
				}
				attribution := detail["attribution"].(map[string]any)
				if attribution["status"] != "unavailable" || attribution["reason"] != "writer_evidence_unavailable" {
					t.Fatalf("attribution: %v", attribution)
				}
				// Host isolation is intentionally not exercised on the development host.
				if response != "kill_and_isolate" {
					for _, trigger := range []string{"decoy_tamper", "ransom_rate"} {
						ruleID, ruleName, eventType := ruleDecoyID, ruleDecoyName, "decoy_tamper"
						if trigger == "ransom_rate" {
							ruleID, ruleName, eventType = ruleRateID, ruleRateName, "ransom_behavior"
						}
						event := g.respondSince(trigger, ruleID, ruleName, files, files, time.Now().Add(-time.Minute))
						if event.Type != eventType {
							t.Fatalf("event type: %s, want %s", event.Type, eventType)
						}
						if event.ActionTaken != "alert_only" || len(event.EvidenceKeys) == 0 {
							t.Fatalf("event: %+v", event)
						}
						if dst := os.Getenv("ALINKSEC_LINUX_ATTRIB_EVIDENCE_FILE"); dst != "" && scenario == "readonly_target" && response == "kill" && trigger == "decoy_tamper" {
							if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
								t.Fatal(err)
							}
							data, err := json.MarshalIndent(event, "", "  ")
							if err != nil {
								t.Fatal(err)
							}
							if err := os.WriteFile(dst, data, 0600); err != nil {
								t.Fatal(err)
							}
						}
						var got map[string]any
						if err := json.Unmarshal([]byte(event.Detail), &got); err != nil {
							t.Fatal(err)
						}
						a := got["attribution"].(map[string]any)
						if a["source"] != "linux_writer_evidence" || a["reason"] != "writer_evidence_unavailable" || got["process"] != nil {
							t.Fatalf("detail: %v", got)
						}
					}
				}
				for _, pid := range pids {
					if err := syscall.Kill(pid, 0); err != nil {
						t.Fatalf("unrelated process/descendant %d lost: %v", pid, err)
					}
				}
			}
		})
	}
}
