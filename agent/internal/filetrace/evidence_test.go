package filetrace

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestConcurrentCapturePolicyAndEvidence(t *testing.T) {
	m := New(t.TempDir())
	m.native = healthy{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	var workers sync.WaitGroup
	workers.Add(3)
	go func() {
		defer workers.Done()
		for range 100 {
			m.Configure([]string{`C:\data`}, 10*time.Second)
			m.Configure(nil, 10*time.Second)
		}
	}()
	go func() {
		defer workers.Done()
		for range 100 {
			m.observe(Write{Path: `C:\data\one`, At: time.Now(), Process: Identity{PID: 10, Created: 100, Image: `C:\writer.exe`}})
		}
	}()
	go func() {
		defer workers.Done()
		for range 100 {
			r := m.Lookup([]string{`C:\data\one`}, time.Now().Add(-time.Second))
			if r.Status == "attributed" && r.Process == nil {
				t.Error("attribution without process identity")
			}
			_ = m.RecentWrites()
		}
	}()
	workers.Wait()
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("capture did not stop")
	}
}

type healthy struct{}

func (healthy) start() error { return nil }
func (healthy) check() error { return nil }
func (healthy) close() error { return nil }

func readyMonitor() *Monitor {
	return &Monitor{roots: []string{`c:\data`}, native: healthy{}, status: "ready", since: time.Now().Add(-time.Minute)}
}

func TestEvidenceRequiresEveryFileAndOneProcessInstance(t *testing.T) {
	now := time.Now()
	since := now.Add(-time.Second)
	p := Identity{PID: 10, Created: 100, Image: `C:\writer.exe`}
	m := readyMonitor()
	m.observe(Write{Path: `C:\data\one`, At: now, Process: p})
	if r := m.Lookup([]string{`c:/DATA/one`}, since); r.Status != "attributed" || *r.Process != p {
		t.Fatalf("exact write = %+v", r)
	}
	if r := m.Lookup([]string{`c:/data/one`, `c:/data/two`}, since); r.Reason != "no_observed_write" {
		t.Fatalf("missing write = %+v", r)
	}
	reused := p
	reused.Created++
	m.observe(Write{Path: `C:\data\one`, At: now, Process: reused})
	if r := m.Lookup([]string{`c:/data/one`}, since); r.Status != "ambiguous" {
		t.Fatalf("PID reuse = %+v", r)
	}
}

func TestGapsStaleUnknownAndCapacityNeverAttribute(t *testing.T) {
	p := Identity{PID: 10, Created: 100, Image: `C:\writer.exe`}
	now := time.Now()
	for _, reason := range []string{"etw_events_lost", "consumer_ended", "capture_stopped"} {
		m := readyMonitor()
		m.observe(Write{Path: `c:\data\file`, At: now, Process: p})
		m.fail(reason)
		if r := m.Lookup([]string{`c:\data\file`}, now.Add(-time.Second)); r.Status != "unavailable" || r.Process != nil {
			t.Fatalf("%s: %+v", reason, r)
		}
	}
	m := readyMonitor()
	m.observe(Write{Path: `c:\data\file`, At: now.Add(-time.Minute), Process: p})
	if r := m.Lookup([]string{`c:\data\file`}, now.Add(-time.Second)); r.Status == "attributed" {
		t.Fatal("stale observation attributed")
	}
	if r := m.Lookup([]string{`c:\data\file`}, now.Add(-2*time.Minute)); r.Reason != "capture_gap" {
		t.Fatalf("gap = %+v", r)
	}
	m.observe(Write{Path: `c:\data\file`, At: now})
	if r := m.Lookup([]string{`c:\data\file`}, now.Add(-time.Second)); r.Reason != "writer_identity_unavailable" {
		t.Fatalf("unknown writer = %+v", r)
	}
	m = readyMonitor()
	for range maxWrites + 1 {
		m.observe(Write{Path: `c:\data\file`, At: now, Process: p})
	}
	if r := m.Lookup([]string{`c:\data\file`}, now.Add(-time.Second)); r.Reason != "write_capacity_exceeded" {
		t.Fatalf("overflow = %+v", r)
	}
}

func TestCachedRootAliasesMatchMixedComponentsWithoutFilesystem(t *testing.T) {
	// These roots need not exist: event matching must depend only on the cached
	// names, even when a later rename makes an event's path impossible to query.
	m := readyMonitor()
	m.roots = []string{`c:\long parent\protected directory`}
	m.rootAliases = []string{`c:\longpa~1\protec~1`}
	for _, path := range []string{
		`c:\long parent\protected directory\中文文件.txt`,
		`C:/LONGPA~1/protected directory/中文文件.txt`,
		`c:\long parent\protec~1\中文文件.txt`,
		`c:\longpa~1\protec~1\中文文件.txt`,
	} {
		if got := m.eventPath(path); got != `c:\long parent\protected directory\中文文件.txt` {
			t.Fatalf("mixed alias %q => %q", path, got)
		}
	}
	for _, path := range []string{
		`c:\longpa~1\protec~10\file`,
		`c:\wrong parent\protec~1\file`,
		`c:\protec~1\longpa~1\file`,
		`c:\longpa~1\file`,
		`d:\longpa~1\protec~1\file`,
	} {
		m.observe(Write{Path: path, At: time.Now()})
		if m.watched(path) || len(m.RecentWrites()) != 0 {
			t.Fatalf("outside root accepted: %q", path)
		}
	}
	// Unknown aliases below a known root cannot be expanded in the callback.
	// Keep them lexical so a long-name lookup cannot receive false attribution.
	p := Identity{PID: 10, Created: 100, Image: `c:\writer.exe`}
	now := time.Now()
	m.observe(Write{Path: `c:\longpa~1\protec~1\unknow~1.txt`, At: now, Process: p})
	if r := m.Lookup([]string{`c:\long parent\protected directory\unknown long name.txt`}, now.Add(-time.Second)); r.Status == "attributed" {
		t.Fatal("unknown leaf alias attributed to a long name")
	}
}

func TestPolicyRootsAndRetentionBoundaries(t *testing.T) {
	m := New(t.TempDir())
	m.Configure([]string{`C:\data`}, 10*time.Second)
	if !m.watched(`c:/data/file`) || m.watched(`c:/database/file`) {
		t.Fatal("path boundary mismatch")
	}
	m.Configure([]string{`C:\data`}, time.Hour)
	if m.Status().Reason != "window_exceeds_retention" {
		t.Fatal("long window accepted")
	}
	if r := m.Lookup([]string{`C:\data\one`}, time.Now()); r.Reason != "window_exceeds_retention" {
		t.Fatal("lookup erased policy boundary")
	}
	m.Configure(nil, 10*time.Second)
	if m.Status().Status != "disabled" {
		t.Fatal("disable failed")
	}
}
