//go:build windows && amd64

package guard

import (
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
	"github.com/alinksec/alinksec-agent/internal/proto"
	"golang.org/x/sys/windows"
)

// Controlled file activity only. No malware or unrelated process is targeted.
func TestWindowsRansomHelper(t *testing.T) {
	role := os.Getenv("ALINKSEC_RANSOM_HELPER")
	if role == "" {
		t.Skip("child fixture")
	}
	path := os.Getenv("ALINKSEC_RANSOM_PATH")
	if role == "capture" {
		m := filetrace.New(os.Getenv("ALINKSEC_RANSOM_WORK"))
		m.Configure([]string{path}, 10*time.Second)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go m.Run(ctx)
		deadline := time.Now().Add(8 * time.Second)
		for m.Status().Status != "ready" && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
		if m.Status().Status != "ready" {
			t.Fatalf("child capture: %+v", m.Status())
		}
	}
	switch role {
	case "write", "rename":
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.WriteString("change!\n"); err != nil {
			t.Fatal(err)
		}
		if err = f.Sync(); err != nil {
			t.Fatal(err)
		}
		f.Close()
		if role == "rename" {
			if err := os.Rename(path, path+".locked"); err != nil {
				t.Fatal(err)
			}
		}
	case "read":
		if _, err := os.ReadFile(path); err != nil {
			t.Fatal(err)
		}
	case "rename_only":
		if err := os.Rename(path, path+".locked"); err != nil {
			t.Fatal(err)
		}
	case "batchrename":
		for _, name := range []string{"batch01.txt", "batch02.txt"} {
			file := filepath.Join(path, name)
			if err := os.WriteFile(file, []byte("modified"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(file, file+".locked"); err != nil {
				t.Fatal(err)
			}
		}
	case "idle", "capture":
	default:
		t.Fatal("unknown fixture role")
	}
	if err := os.WriteFile(os.Getenv("ALINKSEC_RANSOM_READY"), []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Minute)
}

func TestNativeWindowsRansomAttribution(t *testing.T) {
	if os.Getenv("ALINKSEC_RANSOM_NATIVE_REQUIRED") != "true" {
		t.Skip("requires native Windows validation")
	}
	root := t.TempDir()
	work := t.TempDir()
	enabled := true
	cfg := &config.DecoyConfig{Enabled: &enabled, Dirs: []string{root}, WatchTrees: []string{root}, Response: "kill", CountPerDir: 1}
	cfg.Normalize()
	var events []*proto.RptSecurityEvent
	g := New(cfg, nil, work, slog.New(slog.NewTextHandler(io.Discard, nil)), func(e *proto.RptSecurityEvent) { events = append(events, e) })
	g.initialDeploy()
	g.configureAttribution()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { g.fileTrace.Run(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("capture did not stop")
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for g.fileTrace.Status().Status != "ready" && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if s := g.fileTrace.Status(); s.Status != "ready" {
		t.Fatalf("native capture not ready: %+v", s)
	}
	var checks []map[string]any
	add := func(name string, extra map[string]any) {
		if extra == nil {
			extra = map[string]any{}
		}
		extra["name"] = name
		extra["passed"] = true
		checks = append(checks, extra)
	}
	child := func(role, path string) *exec.Cmd {
		exe, _ := os.Executable()
		ready := filepath.Join(t.TempDir(), "ready")
		cmd := exec.Command(exe, "-test.run=^TestWindowsRansomHelper$")
		cmd.Env = append(os.Environ(), "ALINKSEC_RANSOM_HELPER="+role, "ALINKSEC_RANSOM_PATH="+path, "ALINKSEC_RANSOM_READY="+ready, "ALINKSEC_RANSOM_WORK="+work)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(ready); err == nil {
				return cmd
			}
			time.Sleep(30 * time.Millisecond)
		}
		t.Fatal("child did not become ready")
		return nil
	}
	alive := func(cmd *exec.Cmd) bool {
		h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(cmd.Process.Pid))
		if err != nil {
			return false
		}
		defer windows.CloseHandle(h)
		r, err := windows.WaitForSingleObject(h, 0)
		return err == nil && r == uint32(windows.WAIT_TIMEOUT)
	}
	lookup := func(path string, since time.Time, want string) filetrace.Result {
		var r filetrace.Result
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			r = g.fileTrace.Lookup([]string{path}, since)
			if r.Status == want {
				return r
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("lookup want %s for %s since %s: %+v, counters=%v recent=%+v", want, path, since.Format(time.RFC3339Nano), r, g.fileTrace.Counters(), g.fileTrace.RecentWrites())
		return r
	}
	g.healthLoop() // Establish the first completed detector window after capture starts.
	path := newDecoyManager(cfg, work).knownDecoys()[0]
	since := time.Now()
	writer := child("write", path)
	newer := child("idle", "")
	r := lookup(path, since, "attributed")
	if int(r.Process.PID) != writer.Process.Pid {
		t.Fatalf("wrong writer: %+v", r)
	}
	// Deliberately change the creation time while retaining a live PID/image.
	wrong := *r.Process
	wrong.Created++
	if err := filetrace.Terminate(wrong); err == nil || !alive(writer) {
		t.Fatal("identity mismatch was not refused")
	}
	add("identity_mismatch_preserves_process", nil)
	g.healthLoop()
	if len(events) == 0 {
		t.Fatal("decoy health loop did not report tampering")
	}
	event := events[len(events)-1]
	if event.ActionTaken != "killed" {
		t.Fatalf("response: %s", event.Detail)
	}
	deadline = time.Now().Add(2 * time.Second)
	for alive(writer) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if alive(writer) || !alive(newer) {
		t.Fatal("confirmed writer/newer idle process outcome incorrect")
	}
	add("closed_handle_writer_terminated_newer_process_preserved", map[string]any{"event": event, "writerPID": writer.Process.Pid, "unrelatedPID": newer.Process.Pid})

	path = filepath.Join(root, "read.dat")
	os.WriteFile(path, []byte("read-only"), 0600)
	time.Sleep(1200 * time.Millisecond)
	since = time.Now()
	reader := child("read", path)
	time.Sleep(1500 * time.Millisecond)
	event = g.respondSince("decoy_tampered", ruleDecoyID, ruleDecoyName, []string{path}, []string{path}, since)
	if event.ActionTaken != "alert_only" || !alive(reader) || !alive(newer) {
		t.Fatalf("reader misattributed: %s", event.Detail)
	}
	add("reader_and_unrelated_process_not_terminated", map[string]any{"event": event})

	path = filepath.Join(root, "multi.dat")
	since = time.Now()
	first := child("write", path)
	second := child("write", path)
	lookup(path, since, "ambiguous")
	event = g.respondSince("decoy_tampered", ruleDecoyID, ruleDecoyName, []string{path}, []string{path}, since)
	if event.ActionTaken != "alert_only" || !alive(first) || !alive(second) {
		t.Fatalf("ambiguous writers terminated: %s", event.Detail)
	}
	add("multiple_writers_not_terminated", map[string]any{"event": event})

	path = filepath.Join(root, "excluded.dat")
	since = time.Now()
	excluded := child("write", path)
	r = lookup(path, since, "attributed")
	g.mu.Lock()
	next := *g.cfg
	next.ExcludeExes = []string{r.Process.Image}
	g.cfg = &next
	g.mu.Unlock()
	event = g.respondSince("decoy_tampered", ruleDecoyID, ruleDecoyName, []string{path}, []string{path}, since)
	if event.ActionTaken != "alert_only" || !alive(excluded) {
		t.Fatal("excluded writer terminated")
	}
	g.mu.Lock()
	next.ExcludeExes = nil
	g.mu.Unlock()
	add("excluded_writer_not_terminated", map[string]any{"event": event})

	path = filepath.Join(root, "rename.dat")
	if err := os.WriteFile(path, []byte("rename-source"), 0600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1200 * time.Millisecond)
	since = time.Now()
	renamer := child("rename_only", path)
	r = lookup(path, since, "attributed")
	if int(r.Process.PID) != renamer.Process.Pid {
		t.Fatalf("wrong rename writer: %+v", r)
	}
	if r.Writes[0].Operation != "rename" {
		t.Fatalf("not a successful rename operation: %+v", r)
	}
	add("rename_source_attributed_without_write", map[string]any{"attribution": r})
	for _, name := range []string{"batch01.txt", "batch02.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("original"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(1200 * time.Millisecond)
	g.mu.Lock()
	rateCfg := *g.cfg
	rateCfg.RateThreshold = 1
	rateCfg.ExtChangeRatio = 0.5
	g.cfg = &rateCfg
	g.mu.Unlock()
	g.rateLoop()
	rateSince := time.Now()
	batch := child("batchrename", root)
	lookup(filepath.Join(root, "batch01.txt"), rateSince, "attributed")
	lookup(filepath.Join(root, "batch02.txt"), rateSince, "attributed")
	g.rateLoop()
	event = events[len(events)-1]
	if event.Type != "ransom_behavior" || event.ActionTaken != "killed" || alive(batch) || !alive(newer) {
		t.Fatalf("rate detector response: %s", event.Detail)
	}
	add("rate_detector_rename_batch_terminates_only_writer", map[string]any{"event": event})

	cancel()
	<-done
	event = g.respondSince("decoy_tampered", ruleDecoyID, ruleDecoyName, []string{path}, []string{path}, since)
	if event.ActionTaken != "alert_only" || !alive(renamer) {
		t.Fatal("capture stop used stale writer")
	}
	add("capture_stop_invalidates_evidence", map[string]any{"event": event})
	// An independent new monitor must reclaim only its recorded orphan, and a
	// normal restart must be able to acquire the released session/lock.
	m := filetrace.New(work)
	m.Configure([]string{root}, 10*time.Second)
	ctx2, stop2 := context.WithCancel(context.Background())
	defer stop2()
	done2 := make(chan struct{})
	go func() { m.Run(ctx2); close(done2) }()
	deadline = time.Now().Add(8 * time.Second)
	for m.Status().Status != "ready" && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if m.Status().Status != "ready" {
		t.Fatalf("restart failed: %+v", m.Status())
	}
	stop2()
	<-done2
	add("normal_restart_releases_owned_session", nil)
	orphan := child("capture", root)
	if err := orphan.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for alive(orphan) && time.Now().Before(deadline) {
		time.Sleep(30 * time.Millisecond)
	}
	if alive(orphan) {
		t.Fatal("capture owner did not exit")
	}
	m = filetrace.New(work)
	m.Configure([]string{root}, 10*time.Second)
	ctx3, stop3 := context.WithCancel(context.Background())
	defer stop3()
	done3 := make(chan struct{})
	go func() { m.Run(ctx3); close(done3) }()
	deadline = time.Now().Add(8 * time.Second)
	for m.Status().Status != "ready" && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if m.Status().Status != "ready" {
		t.Fatalf("orphan recovery failed: %+v", m.Status())
	}
	stop3()
	<-done3
	add("crashed_owner_session_recovered", nil)
	result := map[string]any{"platform": "windows", "arch": "amd64", "contract": 1, "checks": checks, "osVersion": fmt.Sprintf("%+v", windows.RtlGetVersion())}
	if dst := os.Getenv("ALINKSEC_RANSOM_EVIDENCE_FILE"); dst != "" {
		if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
			t.Fatal(err)
		}
		b, _ := json.MarshalIndent(result, "", "  ")
		if err := os.WriteFile(dst, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
