//go:build windows && amd64

package filetrace

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestWriterSourceHelper(t *testing.T) {
	if os.Getenv("ALINKSEC_FILETRACE_WRITER_HELPER") != "true" {
		t.Skip("child fixture")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	fmt.Println(windows.GetCurrentThreadId())
	time.Sleep(time.Minute)
}

func TestWriterRequiresMatchingEventSourceAndProcessLifetime(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestWriterSourceHelper$")
	cmd.Env = append(os.Environ(), "ALINKSEC_FILETRACE_WRITER_HELPER=true")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	tid, err := strconv.ParseUint(strings.TrimSpace(line), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	at := uint64(time.Now().UnixNano()/100) + 116444736000000000
	id, err := writer(uint32(tid), uint32(cmd.Process.Pid), at)
	if err != nil || id.PID != uint32(cmd.Process.Pid) || id.Created == 0 {
		t.Fatalf("matching source: %+v %v", id, err)
	}
	if _, err := writer(uint32(tid), uint32(os.Getpid()), at); err == nil {
		t.Fatal("another process's event header was accepted")
	}
	if _, err := writer(uint32(tid), uint32(cmd.Process.Pid), id.Created-1); err == nil {
		t.Fatal("pre-creation event timestamp accepted")
	}
}
