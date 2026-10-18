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

func TestFileObjectOwnerTrustBoundary(t *testing.T) {
	writer := Identity{PID: uint32(os.Getpid()) + 100, Created: 100, Image: `C:\writer.exe`}
	for _, owner := range []Identity{writer, {PID: 4}, {PID: uint32(os.Getpid()), Created: 50, Image: `C:\agent.exe`}} {
		if !(openedFile{owner: owner}).accepts(writer) {
			t.Fatalf("verified ordinary/system/collector owner rejected: %+v", owner)
		}
	}
	reused := writer
	reused.Created++
	for _, opened := range []openedFile{{}, {owner: reused}, {owner: Identity{PID: writer.PID + 1, Created: 100, Image: writer.Image}}, {owner: Identity{PID: 4}, identityError: "unverified native source"}} {
		if opened.accepts(writer) {
			t.Fatalf("unverified, reused or unrelated owner accepted: %+v", opened)
		}
	}
	if (openedFile{owner: Identity{PID: 4}}).accepts(Identity{}) {
		t.Fatal("trusted opener bypassed writer identity verification")
	}
}

func TestCollectorOpenRequiresNativeSourceAndCannotIdentifyWriter(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tid, pid := windows.GetCurrentThreadId(), uint32(os.Getpid())
	at := uint64(time.Now().UnixNano()/100) + 116444736000000000
	owner, err := fileOpener(tid, pid, at)
	if err != nil || owner.PID != pid || owner.Created == 0 || owner.Image == "" {
		t.Fatalf("collector opener: %+v %v", owner, err)
	}
	if _, err := fileOpener(tid, pid+100, at); err == nil {
		t.Fatal("forged opener event source accepted")
	}
	if _, err := writer(tid, pid, at); err == nil {
		t.Fatal("collector treated as actionable writer")
	}
}
