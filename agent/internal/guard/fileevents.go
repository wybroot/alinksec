package guard

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"time"

	"github.com/alinksec/alinksec-agent/internal/filewatch"
)

func (g *Guard) virusRoots() ([]string, bool) {
	g.mu.Lock()
	roots := append([]string(nil), g.virusTrees...)
	enabled := g.virusEnabled
	check := g.virusCheck
	g.mu.Unlock()
	return roots, check != nil && (enabled == nil || enabled())
}

// Recheck dispatch authorization for each file. Policy changes must affect the
// next check even when an event batch or recovery traversal is already running.
// The enablement and scan callbacks run outside the policy mutex.
func (g *Guard) virusCheckForPath(path string) VirusCheckFunc {
	g.mu.Lock()
	check, enabled := g.virusCheck, g.virusEnabled
	allowed := false
	for _, root := range g.virusTrees {
		if filewatch.Within(path, root) {
			allowed = true
			break
		}
	}
	g.mu.Unlock()
	if !allowed || check == nil || enabled != nil && !enabled() {
		return nil
	}
	return check
}

func (g *Guard) updateFileWatches() {
	var roots []filewatch.Root
	g.files.mu.Lock()
	for _, f := range g.files.files {
		roots = append(roots, filewatch.Root{Path: filepath.Dir(f.path)})
	}
	g.files.mu.Unlock()
	c := g.cur()
	if c.Enabled == nil || *c.Enabled {
		g.mu.Lock()
		dirs := append([]string(nil), g.watchDirs...)
		g.mu.Unlock()
		for _, p := range dirs {
			roots = append(roots, filewatch.Root{Path: p, Recursive: true})
		}
		for _, p := range c.WatchTrees {
			roots = append(roots, filewatch.Root{Path: p, Recursive: true})
		}
	}
	if paths, on := g.virusRoots(); on {
		for _, p := range paths {
			roots = append(roots, filewatch.Root{Path: p, Recursive: true})
		}
	}
	g.watcher.Update(roots)
}

// FileWatchStatus is bounded heartbeat evidence. It describes notification and
// recovery coverage, never certifies every file clean or attributes a process.
func (g *Guard) FileWatchStatus() string {
	s := g.watcher.Status()
	g.watchMu.Lock()
	d := struct {
		filewatch.Status
		Recovering    bool   `json:"recovering"`
		RecoveryIssue string `json:"recovery_issue"`
		LastSweep     int64  `json:"last_sweep_at"`
	}{s, g.watchRecovery, g.watchIssue, g.watchLastSweep}
	g.watchMu.Unlock()
	b, _ := json.Marshal(d)
	return string(b)
}

func (g *Guard) fileEventLoop() {
	batch := filewatch.Batch{}
	if len(g.eventPending) == 0 {
		batch = g.watcher.Drain(32)
	}
	if batch.Rescan {
		g.virusRescan = true
		g.fileLoop()
		g.healthLoop()
	}
	// Existing pending files keep priority; never truncate work at the scan deadline.
	g.eventPending = append(g.eventPending, batch.Paths...)
	if len(batch.Paths) > 0 {
		for _, event := range g.files.checkPaths(batch.Paths) {
			if g.report != nil {
				g.report(event)
			}
		}
	}
	if len(batch.Paths) > 0 {
		c := g.cur()
		if c.Enabled == nil || *c.Enabled {
			decoys := newDecoyManager(&c, g.workDir).knownDecoys()
		outer:
			for _, p := range batch.Paths {
				for _, d := range decoys {
					if filewatch.Within(d, p) {
						g.healthLoop()
						break outer
					}
				}
			}
		}
	}
	roots, on := g.virusRoots()
	if !on {
		g.virusRunning = false
		g.eventPending = nil
		if g.virusRecovery != nil {
			g.virusRecovery.Close()
			g.virusRecovery = nil
		}
		g.watchMu.Lock()
		g.watchRecovery = false
		g.watchMu.Unlock()
		return
	}
	if !g.virusRunning || !slices.Equal(roots, g.virusScope) {
		if g.virusRecovery != nil {
			g.virusRecovery.Close()
			g.virusRecovery = nil
		}
		g.virusRescan = true
		g.virusScope = append([]string(nil), roots...)
		g.virusRunning = true
	}
	deadline := time.Now().Add(2 * time.Second)
	count := 0
	for len(g.eventPending) > 0 && count < 32 && time.Now().Before(deadline) {
		p := g.eventPending[0]
		g.eventPending = g.eventPending[1:]
		for _, r := range roots {
			if filewatch.Within(p, r) && filewatch.SafePath(p) {
				g.virusSweep([]string{p})
				count++
				break
			}
		}
	}
	if g.virusRecovery == nil && g.virusRescan {
		g.virusRecovery = filewatch.NewSweep(roots)
		g.virusRescan = false
		g.watchMu.Lock()
		g.watchRecovery = true
		g.watchIssue = ""
		g.watchMu.Unlock()
	}
	// Reserve one recovery step even under sustained event traffic, then yield
	// before advancing the cursor if events are waiting. Collection continues
	// independently, so events arriving during a scan get priority next dispatch.
	if g.virusRecovery != nil {
		recoveryDeadline := time.Now().Add(250 * time.Millisecond)
		for n := 0; n < 8 && time.Now().Before(recoveryDeadline); n++ {
			if n > 0 && (len(g.eventPending) > 0 || g.watcher.Status().Pending > 0) {
				break
			}
			p, done := g.virusRecovery.Next(recoveryDeadline)
			if p != "" {
				for _, r := range roots {
					if filewatch.Within(p, r) && filewatch.SafePath(p) {
						g.virusSweep([]string{p})
						break
					}
				}
			}
			if done {
				issue := g.virusRecovery.Issue
				g.virusRecovery.Close()
				g.virusRecovery = nil
				g.watchMu.Lock()
				g.watchRecovery = false
				g.watchIssue = issue
				g.watchLastSweep = time.Now().UnixMilli()
				g.watchMu.Unlock()
				break
			}
		}
	}
}
