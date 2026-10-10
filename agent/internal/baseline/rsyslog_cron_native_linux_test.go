//go:build linux

package baseline

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestNativeRsyslogCronRouting(t *testing.T) {
	if os.Getenv("ALINKSEC_RSYSLOG_CRON_NATIVE_REQUIRED") != "true" {
		t.Skip("disposable rsyslog container only")
	}
	marker, err := os.ReadFile("/usr/local/lib/alinksec-rsyslog-cron-fixture")
	status, statusErr := os.ReadFile("/proc/self/status")
	if _, dockerErr := os.Stat("/.dockerenv"); dockerErr != nil || err != nil || string(marker) != "isolated-rsyslog-cron-routing-v1\n" || statusErr != nil || !strings.Contains(string(status), "CapEff:\t0000000000000000\n") || os.Geteuid() != 0 {
		t.Fatal("isolated Docker fixture without capabilities required")
	}
	raw, err := os.ReadFile("../../../deploy/baseline/packages/rsyslog-cron/linux-baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Items []struct{ Check json.RawMessage }
	}
	if err = json.Unmarshal(raw, &doc); err != nil || len(doc.Items) != 1 {
		t.Fatal("one checked-in rsyslog reference required", err)
	}
	cs, err := ParseCheck(string(doc.Items[0].Check))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("DPKG_ROOT", "/untrusted-database-must-not-be-used")
	// Inspect and validate the exact installed vendor configuration before any
	// private fixture changes. Its commented dedicated cron route is a fail.
	vendor := checkRsyslogCron(cs)
	if vendor.Error || vendor.Passed || !strings.Contains(vendor.Actual, "covered_mask=0x00") {
		t.Fatalf("vendor default should be a complete dedicated-route mismatch: %+v", vendor)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	validate := exec.CommandContext(ctx, "/usr/sbin/rsyslogd", "-N1", "-f", "/etc/rsyslog.conf")
	validate.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	out, validateErr := validate.CombinedOutput()
	cancel()
	if validateErr != nil {
		t.Fatalf("vendor native config: %s %v", out, validateErr)
	}
	t.Logf("native rsyslog vendor validated=true passed=%v error=%v actual=%s", vendor.Passed, vendor.Error, vendor.Actual)
	for _, c := range []struct {
		name, main string
		includes   map[string]string
		mask       uint8
		acl        bool
	}{
		{"all", "cron.* -/var/log/cron.log\n", nil, 255, false},
		{"partial", "cron.info /var/log/cron.log\n", nil, 127, false},
		{"positive-union", "cron.*;cron.err /var/log/cron.log\n", nil, 255, false},
		{"exact-union", "cron.err;cron.=debug /var/log/cron.log\n", nil, 143, false},
		{"negated-threshold", "cron.*;cron.!err /var/log/cron.log\n", nil, 240, false},
		{"negated-exact", "cron.*;cron.!=err /var/log/cron.log\n", nil, 247, false},
		{"none-reset", "cron.*;cron.none;cron.=notice /var/log/cron.log\n", nil, 32, false},
		{"none-negated", "cron.none;cron.!none /var/log/cron.log\n", nil, 255, false},
		{"star-negated", "cron.*;cron.!* /var/log/cron.log\n", nil, 0, false},
		{"priority-aliases", "cron.panic;cron.error;cron.warn;cron.notice;cron.info;cron.debug /var/log/cron.log\n", nil, 255, false},
		{"discard-before", "cron.err ~\ncron.* /var/log/cron.log\n", nil, 240, false},
		{"discard-after", "cron.* /var/log/cron.log\n& stop\n", nil, 255, false},
		{"continuation", "cron.* /var/log/syslog\n& /var/log/cron.log\n", nil, 255, false},
		{"include-order", "$IncludeConfig /etc/rsyslog.d/*.conf\ncron.* /var/log/cron.log\n", map[string]string{"20-route.conf": "cron.* /var/log/cron.log\n", "10-drop.conf": "cron.=debug stop\n", ".05-hidden.conf": "UNSUPPORTED\n", "00-backup.conf.bak": "UNSUPPORTED\n"}, 127, false},
		{"main-before-include", "cron.* /var/log/cron.log\n$IncludeConfig /etc/rsyslog.d/*.conf\n", map[string]string{"10-drop.conf": "cron.* ~\n"}, 255, false},
		{"comment", "#cron.* /var/log/cron.log\n*.*;auth,authpriv.none /var/log/syslog\n", nil, 0, false},
		{"unconditional-stop", "stop\ncron.* /var/log/cron.log\n", nil, 0, false},
		{"config-acl", "cron.* /var/log/cron.log\n", nil, 255, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			// These fixed paths are container-private; no host bind is writable.
			for _, path := range []string{"/etc/rsyslog.d", "/var/log/cron.log", "/var/log/alinksec-control.log", "/var/log/syslog", "/dev/log"} {
				if err := os.RemoveAll(path); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.MkdirAll("/etc/rsyslog.d", 0755); err != nil {
				t.Fatal(err)
			}
			main := "module(load=\"imuxsock\")\n*.* /var/log/alinksec-control.log\n" + c.main
			if err := os.WriteFile("/etc/rsyslog.conf", []byte(main), 0644); err != nil {
				t.Fatal(err)
			}
			for name, body := range c.includes {
				if err := os.WriteFile(filepath.Join("/etc/rsyslog.d", name), []byte(body), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if c.acl {
				if out, err := exec.Command("/usr/bin/setfacl", "-m", "u:65534:r--", "/etc/rsyslog.conf").CombinedOutput(); err != nil {
					t.Fatalf("mandatory ACL fixture %s %v", out, err)
				}
			}
			before := checkRsyslogCron(cs)
			if before.Error != c.acl || before.Passed != (!c.acl && c.mask == 255) || !c.acl && !strings.Contains(before.Actual, fmt.Sprintf("covered_mask=0x%02x", c.mask)) {
				t.Fatalf("wrong Agent result %+v", before)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			check := exec.CommandContext(ctx, "/usr/sbin/rsyslogd", "-N1", "-f", "/etc/rsyslog.conf")
			check.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
			out, err := check.CombinedOutput()
			cancel()
			if err != nil {
				t.Fatalf("native config rejected %s %v", out, err)
			}
			private := t.TempDir()
			stderr, err := os.Create(filepath.Join(private, "stderr"))
			if err != nil {
				t.Fatal(err)
			}
			defer stderr.Close()
			cmd := exec.Command("/usr/sbin/rsyslogd", "-n", "-i", filepath.Join(private, "pid"), "-f", "/etc/rsyslog.conf")
			cmd.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			cmd.Stderr = stderr
			cmd.Stdout = stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			wait := make(chan error, 1)
			go func() { wait <- cmd.Wait() }()
			stopped := false
			defer func() {
				if !stopped {
					_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
					<-wait
				}
			}()
			var conn *net.UnixConn
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				conn, err = net.DialUnix("unixgram", nil, &net.UnixAddr{Name: "/dev/log", Net: "unixgram"})
				if err == nil {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err != nil {
				t.Fatal("native input unavailable", err)
			}
			defer conn.Close()
			_ = conn.SetWriteDeadline(deadline)
			for severity := 0; severity < 8; severity++ {
				if _, err := fmt.Fprintf(conn, "<%d>Oct  8 00:00:00 fixture alinksec: ALINKSEC_CRON_LEVEL_%d", 9*8+severity, severity); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := fmt.Fprintf(conn, "<38>Oct  8 00:00:00 fixture alinksec: ALINKSEC_AUTH_NEGATIVE"); err != nil {
				t.Fatal(err)
			}
			ready := false
			for time.Now().Before(deadline) {
				control, _ := os.ReadFile("/var/log/alinksec-control.log")
				ready = strings.Contains(string(control), "ALINKSEC_AUTH_NEGATIVE")
				for severity := 0; severity < 8; severity++ {
					ready = ready && strings.Contains(string(control), "ALINKSEC_CRON_LEVEL_"+strconv.Itoa(severity))
				}
				if ready {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !ready {
				t.Fatal("all eight cron messages and other-facility control must be processed")
			}
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
			select {
			case err := <-wait:
				stopped = true
				if err != nil {
					t.Fatal("native shutdown", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("native shutdown timed out")
			}
			log, err := os.ReadFile("/var/log/cron.log")
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			var mask uint8
			for severity := 0; severity < 8; severity++ {
				if strings.Contains(string(log), "ALINKSEC_CRON_LEVEL_"+strconv.Itoa(severity)) {
					mask |= 1 << severity
				}
			}
			if mask != c.mask {
				t.Fatalf("native delivered mask=%02x expected=%02x log=%s", mask, c.mask, log)
			}
			// auth.* is excluded only by explicit cron selectors. The reference
			// allows broader selectors, so those have separate finite tests.
			if strings.Contains(string(log), "ALINKSEC_AUTH_NEGATIVE") {
				t.Fatal("cron-only fixture routed another facility")
			}
			t.Logf("native rsyslog cron case=%s delivered_mask=0x%02x passed=%v error=%v actual=%s message=%s", c.name, mask, before.Passed, before.Error, before.Actual, before.Message)
		})
	}
}
