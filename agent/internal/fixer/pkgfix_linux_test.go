//go:build linux

package fixer

import "testing"

func TestInstalledRPMQueryRejectsAmbiguousMultiArchitectureOutput(t *testing.T) {
	if got := rpmInstalledVersion("1\x1f3.0.7\x1f27.el9_4\n"); got != "1:3.0.7-27.el9_4" {
		t.Fatalf("full installed version=%q", got)
	}
	for _, out := range []string{"", "(none)\x1f1.0\x1f1\n", "0\x1f1.0\x1f1\n0\x1f1.0\x1f1\n", "0\x1f1.0\x1f1\r\n"} {
		if rpmInstalledVersion(out) != "" {
			t.Fatal("unresolved package identity was accepted for verification")
		}
	}
}
