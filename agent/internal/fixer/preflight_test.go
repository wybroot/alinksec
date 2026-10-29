package fixer

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func TestUnsupportedActionRejectsWholeRepairBeforeMutation(t *testing.T) {
	for _, action := range []string{"service_restart", "chown", "registry_set", "audit_rule", "unknown"} {
		t.Run(action, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config")
			if err := os.WriteFile(path, []byte("original\n"), 0600); err != nil {
				t.Fatal(err)
			}
			spec := FixSpec{Steps: []Step{{Action: "file_line_ensure", Path: path, Line: "changed"}, {Action: action}}, Check: `{"type":"file_exists","path":"/"}`}
			payload, _ := json.Marshal(spec)
			result := fixOne(&pb.FixItem{Payload: string(payload)}, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)))
			data, err := os.ReadFile(path)
			if err != nil || string(data) != "original\n" {
				t.Fatalf("preflight mutated file: %q, %v", data, err)
			}
			if result.Success || result.RolledBack || result.Verified || !strings.Contains(result.Log, "未执行") {
				t.Fatalf("unexpected outcome: %v", result)
			}
			if (action == "service_restart") != result.RebootRequired {
				t.Fatalf("restart status: %v", result)
			}
		})
	}
}

func TestRestartDependencyAndMissingVerificationRejectBeforeMutation(t *testing.T) {
	for _, restart := range []string{"", "sshd"} {
		path := filepath.Join(t.TempDir(), "must-not-create")
		payload, _ := json.Marshal(FixSpec{RequiresRestart: restart, Steps: []Step{{Action: "file_line_ensure", Path: path, Line: "new"}}})
		result := fixOne(&pb.FixItem{Payload: string(payload)}, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)))
		if result.Success {
			t.Fatal(result)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("unexpected mutation: %v", err)
		}
	}
}

func TestPermissionRepairVerifiesAndRollsBackOnFailedCheck(t *testing.T) {
	for _, passed := range []bool{true, false} {
		path := filepath.Join(t.TempDir(), "account-file")
		if err := os.WriteFile(path, []byte("fixture\n"), 0600); err != nil {
			t.Fatal(err)
		}
		expected := "0644"
		if !passed {
			expected = "0600"
		}
		check, _ := json.Marshal(map[string]any{"type": "file_perm", "target": path, "perm": expected})
		payload, _ := json.Marshal(FixSpec{Steps: []Step{{Action: "chmod", Path: path, Mode: "0644"}}, Check: string(check)})
		result := fixOne(&pb.FixItem{Payload: string(payload)}, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)))
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if passed {
			if !result.Success || !result.Verified || info.Mode().Perm() != 0644 {
				t.Fatalf("repair not verified: %v %v", result, info.Mode())
			}
		} else {
			if result.Success || !result.RolledBack || info.Mode().Perm() != 0600 {
				t.Fatalf("rollback failed: %v %v", result, info.Mode())
			}
		}
	}
}
