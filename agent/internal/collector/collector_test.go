package collector

import "testing"

func TestRedactCommandLine(t *testing.T) {
	got := redactCommandLine([]string{
		"worker", "--token=secret-value", "--password", "p@ss", "--mode=scan",
	})
	want := "worker --token=*** --password *** --mode=scan"
	if got != want {
		t.Fatalf("redactCommandLine() = %q, want %q", got, want)
	}
}

func TestSnapshotMarksOnlyRequestedCollectors(t *testing.T) {
	selected := selectedTasks([]string{"processes"})
	if len(selected) != 1 || selected[0].name != "processes" {
		t.Fatalf("selected = %v, want [processes]", selected)
	}
}
