package filewatch

import (
	"fmt"
	"path/filepath"
	"slices"
	"testing"

	"github.com/fsnotify/fsnotify"
)

func TestPendingEventsDoNotStarveBehindRepeatedWrites(t *testing.T) {
	root := t.TempDir()
	m := New()
	m.Update([]Root{{root, true}})
	m.Drain(MaxPending)
	var hot []string
	for n := 0; n < 32; n++ {
		p := filepath.Join(root, fmt.Sprintf("a-hot-%02d", n))
		hot = append(hot, p)
		m.observe(fsnotify.Event{Name: p, Op: fsnotify.Write})
	}
	waiting := map[string]int{}
	for n := 0; n < 97; n++ {
		p := filepath.Join(root, fmt.Sprintf("z-waiting-%03d", n))
		waiting[p] = 0
		m.observe(fsnotify.Event{Name: p, Op: fsnotify.Write})
	}
	// After each batch the hot paths change again, including paths already
	// waiting. These updates must not take the place of older pending paths.
	for batch := 0; batch < 5; batch++ {
		b := m.Drain(32)
		if b.Rescan {
			t.Fatal("bounded ordinary traffic unexpectedly requested recovery")
		}
		for _, p := range b.Paths {
			if _, ok := waiting[p]; ok {
				waiting[p]++
			}
		}
		for _, p := range hot {
			m.observe(fsnotify.Event{Name: p, Op: fsnotify.Write})
		}
	}
	seen := 0
	for _, count := range waiting {
		if count == 1 {
			seen++
		}
	}
	if seen != len(waiting) {
		t.Fatalf("repeated hot paths starved older events: served %d/%d waiting paths in five batches", seen, len(waiting))
	}
	if s := m.Status(); s.Dropped != 0 || s.Gaps != 0 {
		t.Fatal("accepted traffic was dropped", s)
	}
	t.Log("all 97 waiting paths served within five batches despite 32 repeatedly changing earlier-sort paths")
}

func TestPendingQueueCoalescesAndPreservesFirstArrival(t *testing.T) {
	root := t.TempDir()
	m := New()
	m.Update([]Root{{root, true}})
	m.Drain(MaxPending)
	z, b, a := filepath.Join(root, "z-first"), filepath.Join(root, "b-second"), filepath.Join(root, "a-third")
	for _, p := range []string{z, b, a} {
		m.observe(fsnotify.Event{Name: p, Op: fsnotify.Write})
	}
	for n := 0; n < 100; n++ {
		m.observe(fsnotify.Event{Name: z, Op: fsnotify.Write})
		m.observe(fsnotify.Event{Name: b, Op: fsnotify.Write})
	}
	if s := m.Status(); s.Pending != 3 || s.Dropped != 0 {
		t.Fatal("repeated writes consumed queue capacity", s)
	}
	if got := m.Drain(1).Paths; !slices.Equal(got, []string{z}) {
		t.Fatal("first pending arrival lost its place", got)
	}
	m.observe(fsnotify.Event{Name: z, Op: fsnotify.Write})
	if got := m.Drain(MaxPending).Paths; !slices.Equal(got, []string{b, a, z}) {
		t.Fatal("new change to drained path did not join behind pending work", got)
	}
}

func TestPendingQueueWrapOverflowAndPolicyReplacement(t *testing.T) {
	root := t.TempDir()
	m := New()
	m.Update([]Root{{root, true}})
	m.Drain(MaxPending)
	var original []string
	for n := 0; n < MaxPending; n++ {
		p := filepath.Join(root, fmt.Sprintf("z-original-%04d", n))
		original = append(original, p)
		m.observe(fsnotify.Event{Name: p, Op: fsnotify.Write})
	}
	if got := m.Drain(17).Paths; !slices.Equal(got, original[:17]) {
		t.Fatal("initial queue order changed")
	}
	want := append([]string(nil), original[17:]...)
	for n := 0; n < 17; n++ {
		p := filepath.Join(root, fmt.Sprintf("a-new-%04d", n))
		want = append(want, p)
		m.observe(fsnotify.Event{Name: p, Op: fsnotify.Write})
	}
	// Coalescing at capacity must still work, while new paths are refused and
	// request recovery without replacing accepted pending work.
	for _, p := range []string{original[17], original[MaxPending-1]} {
		m.observe(fsnotify.Event{Name: p, Op: fsnotify.Write})
	}
	for n := 0; n < 2; n++ {
		m.observe(fsnotify.Event{Name: filepath.Join(root, fmt.Sprintf("overflow-%d", n)), Op: fsnotify.Write})
	}
	if s := m.Status(); s.Pending != MaxPending || s.Dropped != 2 || s.Gaps != 1 {
		t.Fatal("capacity or overflow evidence changed", s)
	}
	var got []string
	rescans := 0
	for m.Status().Pending > 0 {
		b := m.Drain(31)
		got = append(got, b.Paths...)
		if b.Rescan {
			rescans++
		}
	}
	if !slices.Equal(got, want) || rescans != 1 || len(m.Drain(1).Paths) != 0 {
		t.Fatalf("accepted queue was reordered/lost during wrap or overflow: got=%d want=%d rescans=%d", len(got), len(want), rescans)
	}
	m.observe(fsnotify.Event{Name: original[0], Op: fsnotify.Write})
	other := t.TempDir()
	m.Update([]Root{{other, true}})
	m.observe(fsnotify.Event{Name: original[1], Op: fsnotify.Write})
	current := filepath.Join(other, "current")
	m.observe(fsnotify.Event{Name: current, Op: fsnotify.Write})
	if b := m.Drain(MaxPending); !b.Rescan || !slices.Equal(b.Paths, []string{current}) || m.Status().Pending != 0 {
		t.Fatal("policy replacement retained old queue entries", b, m.Status())
	}
}
