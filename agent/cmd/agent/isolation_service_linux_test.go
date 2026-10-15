//go:build linux

package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/isolation"
)

func prepareIsolationNative(t *testing.T, work, probeIP string) {
	t.Helper()
	unit := "/etc/systemd/system/alinksec-agent-isolation-watchdog.service"
	if _, err := os.Lstat(unit); !os.IsNotExist(err) {
		t.Fatal("refusing an existing isolation watchdog unit", err)
	}
	for _, exe := range []string{"iptables", "ip6tables", "iptables-save", "ip6tables-save"} {
		if _, err := exec.LookPath(exe); err != nil {
			t.Fatal(err)
		}
	}
	digest := sha256.Sum256([]byte(work))
	marker := fmt.Sprintf("alinksec-native-isolation-%x", digest[:6])
	args := []string{"OUTPUT", "-p", "tcp", "-d", probeIP, "--dport", "443", "-m", "comment", "--comment", marker, "-j", "ACCEPT"}
	nativeIsolationCommand(t, "iptables", append([]string{"-A"}, args...)...)
	t.Cleanup(func() {
		if b, err := os.ReadFile(unit); err == nil {
			if !strings.Contains(string(b), testUnitArg(work)) {
				t.Error("unrelated isolation watchdog during fixture cleanup")
				return
			}
			nativeIsolationCommand(t, "systemctl", "stop", "alinksec-agent-isolation-watchdog.service")
			l, err := isolation.Current(work)
			if err == nil && l.Phase != "finished" {
				t.Error("isolation cleanup still pending; preserve independent recovery service")
				return
			}
			nativeIsolationCommand(t, "systemctl", "disable", "alinksec-agent-isolation-watchdog.service")
			os.Remove(unit)
			nativeIsolationCommand(t, "systemctl", "daemon-reload")
		}
		nativeIsolationCommand(t, "iptables", append([]string{"-D"}, args...)...)
	})
}
func isolationNativePolicy(t *testing.T) string {
	t.Helper()
	var all strings.Builder
	for _, exe := range []string{"iptables-save", "ip6tables-save"} {
		out := nativeIsolationCommand(t, exe)
		for _, line := range strings.Split(out, "\n") {
			if !strings.HasPrefix(line, "#") {
				all.WriteString(regexp.MustCompile(`\[\d+:\d+\]`).ReplaceAllString(line, "[counter]"))
				all.WriteByte('\n')
			}
		}
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(all.String())))
}
func assertIsolationNativeRules(t *testing.T, l *isolation.Lease) {
	t.Helper()
	chain := "ALKISO_" + l.ID[:16]
	tag := "alinksec-isolation:" + l.ID
	for _, exe := range []string{"iptables", "ip6tables"} {
		rules := nativeIsolationCommand(t, exe, "-S", chain)
		if !strings.Contains(rules, "-j DROP") || !strings.Contains(rules, tag) {
			t.Fatalf("missing owned dual-stack deny rules: %s", rules)
		}
		for _, hook := range []string{"INPUT", "OUTPUT", "FORWARD"} {
			nativeIsolationCommand(t, exe, "-C", hook, "-m", "comment", "--comment", tag, "-j", chain)
		}
	}
}
func crashIsolationNativeOwner(t *testing.T) {
	t.Helper()
	nativeIsolationCommand(t, "systemctl", "kill", "--signal=SIGKILL", "--kill-whom=main", "alinksec-agent-isolation-watchdog.service")
}
func waitIsolationNativeRemoved(t *testing.T) {
	t.Helper()
	for i := 0; i < 40; i++ {
		if _, err := os.Lstat("/etc/systemd/system/alinksec-agent-isolation-watchdog.service"); os.IsNotExist(err) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("completed isolation watchdog unit was not removed")
}
