//go:build windows

package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestServiceCrashOutputRetainsPanicWithBoundedHistory(t *testing.T) {
	if work := os.Getenv("ALINKSEC_CRASH_TEST_CHILD"); work != "" {
		if err := retainServiceCrashOutput(work); err != nil {
			t.Fatal(err)
		}
		panic("controlled service crash regression")
	}
	work := t.TempDir()
	for i := 0; i < 4; i++ {
		cmd := exec.Command(os.Args[0], "-test.run=^TestServiceCrashOutputRetainsPanicWithBoundedHistory$")
		cmd.Env = append(os.Environ(), "ALINKSEC_CRASH_TEST_CHILD="+work)
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		if err := cmd.Run(); err == nil {
			t.Fatal("controlled panic unexpectedly succeeded")
		}
	}
	files, err := filepath.Glob(filepath.Join(work, "service-crashes", "crash-*.log"))
	if err != nil || len(files) != 3 {
		t.Fatalf("unbounded or missing crash history: %v %v", files, err)
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil || !bytes.Contains(data, []byte("panic: controlled service crash regression")) {
			t.Fatalf("SCM crash reason was lost: %q %v", data, err)
		}
	}
}
