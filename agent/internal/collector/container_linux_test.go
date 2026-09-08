//go:build linux

package collector

import "testing"

func TestKubernetesPodArgsLimitsToNode(t *testing.T) {
	args := kubernetesPodArgs("worker-a")
	want := []string{"get", "pods", "--all-namespaces", "--field-selector", "spec.nodeName=worker-a", "-o", "json"}
	if len(args) != len(want) {
		t.Fatalf("args = %v, want %v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q", i, args[i], want[i])
		}
	}
}
