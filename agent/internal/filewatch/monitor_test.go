package filewatch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

func TestWindowsCaseAliasesDoNotResetPendingWork(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows path identity")
	}
	root := t.TempDir()
	a, b := Root{strings.ToUpper(root), true}, Root{strings.ToLower(root), true}
	m := New()
	m.Update([]Root{a, b})
	m.Drain(MaxPending)
	m.observe(fsnotify.Event{Name: filepath.Join(root, "queued.txt"), Op: fsnotify.Write})
	m.Update([]Root{b, a})
	if m.Status().Pending != 1 {
		t.Fatal("equivalent policy cleared pending work")
	}
}

type failingRegistrar struct {
	fail  bool
	paths map[string]bool
	adds  int
}

func (w *failingRegistrar) Add(path string) error {
	if w.fail {
		return errors.New("controlled registration failure")
	}
	if w.paths == nil {
		w.paths = map[string]bool{}
	}
	w.paths[path] = true
	w.adds++
	return nil
}
func (w *failingRegistrar) Remove(path string) error { delete(w.paths, path); return nil }
func (w *failingRegistrar) WatchList() []string {
	var paths []string
	for p := range w.paths {
		paths = append(paths, p)
	}
	return paths
}

func TestRegistrationFailureIsVisibleAndRecoveryRequestsRescan(t *testing.T) {
	m := New()
	m.Update([]Root{{t.TempDir(), true}})
	w := &failingRegistrar{fail: true}
	watched := map[string]os.FileInfo{}
	m.reconcile(context.Background(), w, watched)
	if s := m.Status(); s.State != "degraded" || s.Issue != "watch_add_failed" || !m.Drain(10).Rescan {
		t.Fatal(s)
	}
	w.fail = false
	m.reconcile(context.Background(), w, watched)
	if s := m.Status(); s.State != "watching" || s.Watches < 1 || !m.Drain(10).Rescan {
		t.Fatal(s)
	}
}

func TestLargeTreePreservesLaterRootsAndNativeEvents(t *testing.T) {
	base := t.TempDir()
	large, later := filepath.Join(base, "a-large"), filepath.Join(base, "z-later")
	for _, path := range []string{large, later} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for n := 0; n < MaxWatches+16; n++ {
		if err := os.Mkdir(filepath.Join(large, fmt.Sprintf("%04d", n)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	m := New()
	m.Update([]Root{{large, true}, {later, true}})
	w := &failingRegistrar{}
	m.reconcile(context.Background(), w, map[string]os.FileInfo{})
	if s := m.Status(); !w.paths[later] || !w.paths[filepath.Dir(later)] || s.Watches > MaxWatches || s.Issue != "watch_budget" {
		t.Fatal("large tree starved a configured root or concealed incomplete coverage", s)
	}
	// Exercise actual OS notifications as well as the registrar selection.
	native, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer native.Close()
	m.reconcile(context.Background(), native, map[string]os.FileInfo{})
	path := filepath.Join(later, "harmless.txt")
	if err := os.WriteFile(path, []byte("harmless native notification probe"), 0600); err != nil {
		t.Fatal(err)
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case event := <-native.Events:
			if event.Name == path && event.Op&(fsnotify.Create|fsnotify.Write) != 0 {
				return
			}
		case err := <-native.Errors:
			t.Fatal(err)
		case <-timer.C:
			t.Fatal("later root did not receive its actual native event")
		}
	}
}

func TestRemovedNativeWatchIsReinstalledEvenWhenDirectoryIdentityMatches(t *testing.T) {
	root := t.TempDir()
	m := New()
	m.Update([]Root{{root, true}})
	w := &failingRegistrar{}
	watched := map[string]os.FileInfo{}
	m.reconcile(context.Background(), w, watched)
	m.Drain(MaxPending)
	before := w.adds
	delete(w.paths, root) // automatic kernel watch removal, unchanged stat identity
	m.reconcile(context.Background(), w, watched)
	if w.adds <= before || !w.paths[root] || !m.Drain(MaxPending).Rescan {
		t.Fatal("detached native watch was trusted")
	}
	before = w.adds
	m.observe(fsnotify.Event{Name: root, Op: fsnotify.Remove})
	m.reconcile(context.Background(), w, watched)
	if w.adds <= before || !m.Drain(MaxPending).Rescan {
		t.Fatal("directory removal did not invalidate reused identity")
	}
	before = w.adds
	m.gap("kernel_overflow_or_error")
	m.reconcile(context.Background(), w, watched)
	if w.adds <= before || !m.Drain(MaxPending).Rescan {
		t.Fatal("kernel gap retained possibly stale native watches")
	}
}

func TestBoundedCollectionOverflowAndPolicyReplacement(t *testing.T) {
	root := t.TempDir()
	m := New()
	m.Update([]Root{{root, true}})
	m.Drain(MaxPending)
	for n := 0; n < MaxPending+50; n++ {
		m.observe(fsnotify.Event{Name: filepath.Join(root, fmt.Sprint(n)), Op: fsnotify.Write})
	}
	s := m.Status()
	if s.Pending != MaxPending || s.Dropped != 50 || s.Gaps != 1 {
		t.Fatal(s)
	}
	b := m.Drain(17)
	if len(b.Paths) != 17 || !b.Rescan || m.Status().Pending != MaxPending-17 {
		t.Fatal(b, m.Status())
	}
	other := t.TempDir()
	m.Update([]Root{{other, true}})
	if m.Status().Pending != 0 {
		t.Fatal("old-policy queue retained")
	}
	m.observe(fsnotify.Event{Name: filepath.Join(root, "old"), Op: fsnotify.Write})
	if len(m.Drain(10).Paths) != 0 {
		t.Fatal("removed scope accepted")
	}
	m.gap("kernel_overflow_or_error")
	if !m.Drain(10).Rescan || m.Status().Gaps != 2 {
		t.Fatal("kernel gap did not request recovery")
	}
}

func TestScopeAndIncrementalSweepDoNotFollowLinksOrStarve(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	for n := 0; n < 77; n++ {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("%03d", n)), []byte("harmless"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	os.Mkdir(filepath.Join(root, ".hidden"), 0700)
	os.WriteFile(filepath.Join(root, ".hidden", "skip"), nil, 0600)
	if err := os.Symlink(outside, filepath.Join(root, "link")); err == nil && SafePath(filepath.Join(root, "link", "not-created")) {
		t.Fatal("link ancestor accepted")
	}
	s := NewSweep([]string{root})
	defer s.Close()
	seen := map[string]bool{}
	for n := 0; n < 1000; n++ {
		p, done := s.Next(time.Now().Add(time.Second))
		if p != "" {
			seen[p] = true
		}
		if done {
			break
		}
	}
	if len(seen) != 77 {
		t.Fatal("recovery lost later files", len(seen))
	}
	if Within(root+"-sibling", root) || inScope(filepath.Join(root, ".hidden", "skip"), []Root{{root, true}}) || inScope(filepath.Join(root, "sub", "file"), []Root{{root, false}}) {
		t.Fatal("scope escaped")
	}
}

func TestConcurrentCollectionDrainAndPolicyUpdates(t *testing.T) {
	root := t.TempDir()
	m := New()
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for n := 0; n < 1000; n++ {
			m.Update([]Root{{root, true}})
		}
	}()
	go func() {
		defer wg.Done()
		for n := 0; n < 1000; n++ {
			m.observe(fsnotify.Event{Name: filepath.Join(root, fmt.Sprint(n)), Op: fsnotify.Write})
		}
	}()
	go func() {
		defer wg.Done()
		for n := 0; n < 1000; n++ {
			m.Drain(32)
			m.Status()
		}
	}()
	wg.Wait()
}

func TestCancellationClosesNativeWatcher(t *testing.T) {
	m := New()
	m.Update([]Root{{t.TempDir(), true}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("native watcher did not stop")
	}
}
