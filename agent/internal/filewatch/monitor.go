// Package filewatch collects filesystem invalidations, never process attribution.
// Contents and actions are revalidated by the existing protection engines.
package filewatch

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

const (
	MaxRoots     = 128
	MaxWatches   = 1024
	MaxPending   = 2048
	MaxDepth     = 5
	MaxEntries   = 20000
	MaxPathBytes = 4096
)

type Root struct {
	Path      string
	Recursive bool
}

type Status struct {
	State     string `json:"state"`
	Issue     string `json:"issue"`
	Backend   string `json:"backend"`
	Roots     int    `json:"roots"`
	Watches   int    `json:"watches"`
	Pending   int    `json:"pending"`
	Dropped   uint64 `json:"dropped"`
	Gaps      uint64 `json:"gaps"`
	LastEvent int64  `json:"last_event_at"`
	LastSync  int64  `json:"last_sync_at"`
}

type Batch struct {
	Paths  []string
	Rescan bool
}

type Monitor struct {
	mu       sync.Mutex
	roots    []Root
	pending  map[string]string
	rescan   bool
	topology bool
	revision uint64
	status   Status
	wake     chan struct{}
}

func New() *Monitor {
	backend := "unsupported"
	if runtime.GOOS == "linux" {
		backend = "inotify"
	}
	if runtime.GOOS == "windows" {
		backend = "ReadDirectoryChangesW"
	}
	return &Monitor{pending: map[string]string{}, wake: make(chan struct{}, 1), status: Status{State: "starting", Backend: backend}}
}

func key(p string) string {
	p = filepath.Clean(p)
	if runtime.GOOS == "windows" {
		p = strings.ToLower(p)
	}
	return p
}

func Within(path, root string) bool {
	rel, err := filepath.Rel(key(root), key(path))
	return err == nil && rel != ".." && !filepath.IsAbs(rel) && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// SafePath rejects symlinks/junctions in every existing component. It is a
// dispatch filter, not authority to restore or quarantine a file (TOCTOU).
func SafePath(path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		s, err := os.Lstat(p)
		if err != nil && !os.IsNotExist(err) {
			return false
		}
		if err == nil && (s.Mode()&os.ModeSymlink != 0 || (!s.IsDir() && p != filepath.Clean(path))) {
			return false
		}
		if filepath.Dir(p) == p {
			return true
		}
	}
}

func (m *Monitor) Update(roots []Root) {
	next := make([]Root, 0, len(roots))
	seen := map[string]int{}
	for _, r := range roots {
		if !filepath.IsAbs(r.Path) {
			continue
		}
		r.Path = filepath.Clean(r.Path)
		id := key(r.Path) + fmtBool(r.Recursive)
		if index, ok := seen[id]; ok {
			// Case aliases must not make policy snapshots depend on map order.
			if r.Path < next[index].Path {
				next[index] = r
			}
		} else {
			seen[id] = len(next)
			next = append(next, r)
		}
	}
	sort.Slice(next, func(i, j int) bool {
		return key(next[i].Path)+fmtBool(next[i].Recursive) < key(next[j].Path)+fmtBool(next[j].Recursive)
	})
	m.mu.Lock()
	defer m.mu.Unlock()
	if reflect.DeepEqual(m.roots, next) {
		return
	}
	m.roots = next
	m.revision++
	m.status.State = "starting"
	m.status.Issue = ""
	m.pending = map[string]string{}
	m.rescan = true
	m.topology = true
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func fmtBool(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func inScope(path string, roots []Root) bool {
	for _, r := range roots {
		if !Within(path, r.Path) {
			continue
		}
		rel, _ := filepath.Rel(r.Path, path)
		parts := strings.Split(rel, string(filepath.Separator))
		if len(parts) > MaxDepth+1 || !r.Recursive && len(parts) > 1 {
			continue
		}
		hidden := false
		for _, p := range parts[:len(parts)-1] {
			if strings.HasPrefix(p, ".") && p != "." {
				hidden = true
			}
		}
		if !hidden {
			return true
		}
	}
	return false
}

func (m *Monitor) observe(e fsnotify.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e.Has(fsnotify.Create | fsnotify.Remove | fsnotify.Rename) {
		m.topology = true
	}
	if !inScope(e.Name, m.roots) {
		return
	}
	if len(e.Name) > MaxPathBytes {
		m.status.Dropped++
		m.status.Gaps++
		m.rescan = true
		m.status.State = "degraded"
		m.status.Issue = "path_limit"
		return
	}
	m.status.LastEvent = time.Now().UnixMilli()
	k := key(e.Name)
	if _, ok := m.pending[k]; !ok && len(m.pending) >= MaxPending {
		m.status.Dropped++
		if !m.rescan {
			m.status.Gaps++
		}
		m.rescan = true
		m.status.State = "degraded"
		m.status.Issue = "queue_overflow"
		return
	}
	m.pending[k] = filepath.Clean(e.Name)
}

func (m *Monitor) gap(issue string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rescan = true
	m.topology = true
	m.status.Gaps++
	m.status.State = "degraded"
	m.status.Issue = issue
}

func (m *Monitor) Drain(limit int) Batch {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit < 1 || limit > MaxPending {
		limit = MaxPending
	}
	b := Batch{Rescan: m.rescan}
	m.rescan = false
	// Sorting makes bounded batches deterministic and allows queued work to drain.
	keys := make([]string, 0, len(m.pending))
	for k := range m.pending {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if len(b.Paths) == limit {
			break
		}
		b.Paths = append(b.Paths, m.pending[k])
		delete(m.pending, k)
	}
	return b
}

func (m *Monitor) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.status
	s.Pending = len(m.pending)
	return s
}

func (m *Monitor) Run(ctx context.Context) {
	if m.status.Backend == "unsupported" {
		m.gap("unsupported")
		return
	}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	var w *fsnotify.Watcher
	watched := map[string]os.FileInfo{}
	var readerDone chan struct{}
	defer func() {
		if w != nil {
			w.Close()
			<-readerDone
		}
	}()
	var lastSync time.Time
	for {
		if w == nil {
			var err error
			w, err = fsnotify.NewBufferedWatcher(256)
			if err != nil {
				m.gap("watcher_unavailable")
			} else {
				readerDone = make(chan struct{})
				go func(w *fsnotify.Watcher, done chan struct{}) {
					defer close(done)
					for {
						select {
						case e, ok := <-w.Events:
							if !ok {
								return
							}
							m.observe(e)
						case _, ok := <-w.Errors:
							if !ok {
								return
							}
							m.gap("kernel_overflow_or_error")
						}
					}
				}(w, readerDone)
			}
		}
		m.mu.Lock()
		dirty := m.topology
		m.mu.Unlock()
		if w != nil && (dirty || time.Since(lastSync) >= 30*time.Second) {
			m.reconcile(ctx, w, watched)
			lastSync = time.Now()
		}
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
		case <-tick.C:
		}
		if w != nil {
			select {
			case <-readerDone:
				w.Close()
				w = nil
				watched = map[string]os.FileInfo{}
				m.gap("watcher_closed")
			default:
			}
		}
	}
}

// Registration is bounded independently of the number of files. Parent anchors
// detect root replacement/missing-root creation without watching outside trees.
type registrar interface {
	Add(string) error
	Remove(string) error
}

func (m *Monitor) reconcile(ctx context.Context, w registrar, watched map[string]os.FileInfo) {
	m.mu.Lock()
	roots := append([]Root(nil), m.roots...)
	rev := m.revision
	m.topology = false
	m.mu.Unlock()
	wanted := map[string]os.FileInfo{}
	issue := ""
	if len(roots) > MaxRoots {
		roots = roots[:MaxRoots]
		issue = "root_limit"
	}
	entries := 0
	deadline := time.Now().Add(time.Second)
	var walk func(string, int, bool)
	walk = func(path string, depth int, recursive bool) {
		if ctx.Err() != nil {
			return
		}
		if entries >= MaxEntries || len(wanted) >= MaxWatches || time.Now().After(deadline) {
			issue = "watch_budget"
			return
		}
		entries++
		if !SafePath(path) {
			issue = "unsafe_path"
			return
		}
		s, err := os.Lstat(path)
		if err != nil || !s.IsDir() {
			issue = "root_unavailable"
			return
		}
		wanted[path] = s
		if !recursive || depth >= MaxDepth {
			return
		}
		d, err := os.Open(path)
		if err != nil {
			issue = "directory_unreadable"
			return
		}
		defer d.Close()
		for entries < MaxEntries && len(wanted) < MaxWatches && time.Now().Before(deadline) {
			list, err := d.ReadDir(64)
			for _, e := range list {
				if entries >= MaxEntries {
					issue = "watch_budget"
					break
				}
				entries++
				if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
					walk(filepath.Join(path, e.Name()), depth+1, true)
				}
			}
			if err != nil {
				break
			}
		}
		if entries >= MaxEntries || len(wanted) >= MaxWatches || time.Now().After(deadline) {
			issue = "watch_budget"
		}
	}
	for _, r := range roots {
		if len(r.Path) > MaxPathBytes {
			issue = "path_limit"
			continue
		}
		parent := filepath.Dir(r.Path)
		for {
			if s, err := os.Lstat(parent); err == nil && s.IsDir() {
				walk(parent, 0, false)
				break
			}
			if filepath.Dir(parent) == parent {
				break
			}
			parent = filepath.Dir(parent)
		}
		walk(r.Path, 0, r.Recursive)
	}
	changed := false
	for p, old := range watched {
		if cur, ok := wanted[p]; !ok || !os.SameFile(old, cur) {
			_ = w.Remove(p)
			delete(watched, p)
			changed = true
		}
	}
	for p, info := range wanted {
		if _, ok := watched[p]; ok {
			continue
		}
		if !SafePath(p) {
			issue = "unsafe_path"
			continue
		}
		if err := w.Add(p); err != nil {
			issue = "watch_add_failed"
			continue
		}
		after, err := os.Lstat(p)
		if err != nil || !os.SameFile(info, after) || !SafePath(p) {
			_ = w.Remove(p)
			issue = "path_changed"
			continue
		}
		watched[p] = info
		changed = true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if changed {
		m.rescan = true
	}
	m.status.Roots = len(roots)
	m.status.Watches = len(watched)
	m.status.LastSync = time.Now().UnixMilli()
	if rev != m.revision {
		m.topology = true
		return
	}
	m.status.State = "watching"
	m.status.Issue = issue
	if len(roots) == 0 {
		m.status.State = "disabled"
	}
	if issue != "" {
		m.status.State = "degraded"
		m.status.Gaps++
		m.rescan = true
	}
}
