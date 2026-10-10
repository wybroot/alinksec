//go:build linux

package baseline

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestNonregularOversizedAndIncompleteFilesCannotPass(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	large := filepath.Join(dir, "large")
	f, err := os.Create(large)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(maxFileBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	tooMany := filepath.Join(dir, "many-lines")
	if err := os.WriteFile(tooMany, []byte(strings.Repeat("safe\n", 16385)), 0600); err != nil {
		t.Fatal(err)
	}
	tooLong := filepath.Join(dir, "long-line")
	if err := os.WriteFile(tooLong, []byte(strings.Repeat("x", 1024*1024)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fifo, large, tooMany, tooLong} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			start := time.Now()
			result := checkFileLine(&CheckSpec{Type: "file_line", Target: path, Operator: "not_contains", Expected: "forbidden", TimeoutMs: 5000})
			if result.Passed || !result.Error {
				t.Fatalf("invalid file was treated as a complete assertion: %+v", result)
			}
			if time.Since(start) > time.Second {
				t.Fatal("file rejection blocked")
			}
		})
	}
}

func TestExpiredEmptyFileCannotPassAnAbsenceCheck(t *testing.T) {
	file := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readLinesWithin(file, time.Now().Add(-time.Second)); err == nil {
		t.Fatal("expired empty-file read was accepted as complete")
	}
}

func TestCommandTimeoutClosesInheritedPipesAndStopsDescendants(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	result := executeBaselineCommand(ctx, exec.CommandContext(ctx, "/bin/sh", "-c", "sleep 30 & wait"), &CheckSpec{TimeoutMs: 100, Operator: "eq", Expected: "ok"})
	if !result.Error || result.Passed || !strings.Contains(result.Message, "超时") {
		t.Fatalf("result: %+v", result)
	}
	if time.Since(start) > time.Second {
		t.Fatal("inherited pipes outlived the deadline")
	}
}

func TestCommandOutputLimitStopsExecutionBeforeItsDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	result := executeBaselineCommand(ctx, exec.CommandContext(ctx, "/bin/sh", "-c", "head -c 131072 /dev/zero; sleep 30"), &CheckSpec{TimeoutMs: 10000, Operator: "eq", Expected: "ok"})
	if !result.Error || result.Passed || !strings.Contains(result.Message, "64 KiB") || len(result.Actual) > 2051 {
		t.Fatalf("result: error=%v message=%s bytes=%d", result.Error, result.Message, len(result.Actual))
	}
	if time.Since(start) > time.Second {
		t.Fatal("output limit did not terminate execution")
	}
}

func TestExitedShellCannotLeaveABackgroundCommandRunning(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "orphan-marker")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := executeBaselineCommand(ctx, exec.CommandContext(ctx, "/bin/sh", "-c", "(sleep 1; touch \"$1\") & exit 0", "baseline-test", marker), &CheckSpec{TimeoutMs: 5000, Operator: "eq", Expected: ""})
	if !result.Error || result.Passed {
		t.Fatalf("incomplete command was considered successful: %+v", result)
	}
	time.Sleep(time.Second)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("orphan executed after the check returned: %v", err)
	}
}
