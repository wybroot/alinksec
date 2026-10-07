//go:build linux

package baseline

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func rsyslogProbe(context.Context, int) ItemResult {
	return ItemResult{Actual: "ii \t" + rsyslogPackageVersion}
}

func rsyslogFixture(t *testing.T, main string, includes map[string]string) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("numeric UID0 fixture requires root")
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/rsyslog.d"), 0755); err != nil {
		t.Fatal(err)
	}
	for name, content := range includes {
		if err := os.WriteFile(filepath.Join(root, "etc/rsyslog.d", name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "etc/rsyslog.conf"), []byte(main), 0644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestRsyslogCronSelectorNativeSemantics(t *testing.T) {
	for selector, want := range map[string]uint8{
		"cron.*": 255, "cron.info": 127, "cron.=err": 8, "cron.*;cron.err": 255,
		"cron.err;cron.=debug": 143, "*.*;cron.none": 0, "cron.*;cron.!err": 240,
		"cron.*;cron.!=err": 247, "cron.none;cron.!none": 255, "cron.*;cron.!*": 0,
		"auth,cron.warning": 31, "auth.*": 0, "*.debug;auth,authpriv.none": 255,
		"cron.*;cron.none;cron.=notice": 32, "cron.error": 15, "cron.panic": 1,
	} {
		got, err := rsyslogCronSelector(selector)
		if err != nil || got != want {
			t.Fatalf("%s: %02x want %02x err=%v", selector, got, want, err)
		}
	}
	for _, selector := range []string{"cron", "cron.", ".info", "cron.none;", "cron.=*", "cron.=none", "cron.=!err", "cron.8", "9.*", "crontab.*", "cron..info", "cron .info", "CRON.*", "cron,.*"} {
		if _, err := rsyslogCronSelector(selector); err == nil {
			t.Fatalf("accepted %s", selector)
		}
	}
}

func TestRsyslogCronRoutingGraph(t *testing.T) {
	for _, c := range []struct {
		name, main string
		includes   map[string]string
		mask       uint8
		input      bool
		error      bool
	}{
		{"direct", "module(load=\"imuxsock\")\ncron.* -/var/log/cron.log\n", nil, 255, true, false},
		{"comment", "module(load=\"imuxsock\") # local input\n#cron.* /var/log/cron.log\n*.* /var/log/syslog\n", nil, 0, true, false},
		{"partial", "module(load=\"imuxsock\")\ncron.info /var/log/cron.log\n", nil, 127, true, false},
		{"stopped-before", "module(load=\"imuxsock\")\ncron.err ~\ncron.* /var/log/cron.log\n", nil, 240, true, false},
		{"stopped-after", "module(load=\"imuxsock\")\ncron.* /var/log/cron.log\n& stop\n", nil, 255, true, false},
		{"unconditional-stop", "module(load=\"imuxsock\")\nstop\ncron.* /var/log/cron.log\n", nil, 0, true, false},
		{"continuation", "module(load=\"imuxsock\")\ncron.* /var/log/syslog\n& /var/log/cron.log\n", nil, 255, true, false},
		{"input-off", "module(load=\"imuxsock\" SysSock.Use=\"off\")\ncron.* /var/log/cron.log\n", nil, 255, false, false},
		{"no-input", "cron.* /var/log/cron.log\n", nil, 255, false, false},
		{"include-before-main", "module(load=\"imuxsock\")\n$IncludeConfig /etc/rsyslog.d/*.conf\ncron.* /var/log/cron.log\n", map[string]string{"20-drop.conf": "cron.err stop\n", "90-route.conf": "cron.=debug /var/log/syslog\n", ".10-hidden.conf": "UNSUPPORTED\n", "10.backup": "UNSUPPORTED\n"}, 240, true, false},
		{"main-before-include", "module(load=\"imuxsock\")\ncron.* /var/log/cron.log\n$IncludeConfig /etc/rsyslog.d/*.conf\n", map[string]string{"10-drop.conf": "cron.* ~\n"}, 255, true, false},
		{"include-order", "module(load=\"imuxsock\")\n$IncludeConfig /etc/rsyslog.d/*.conf\n", map[string]string{"10-drop.conf": "cron.=debug ~\n", "20-route.conf": "cron.* /var/log/cron.log\n"}, 127, true, false},
		{"include-empty", "module(load=\"imuxsock\")\n$IncludeConfig /etc/rsyslog.d/*.conf\ncron.* /var/log/cron.log\n", nil, 255, true, false},
		{"unsupported-after-stop", "module(load=\"imuxsock\")\nstop\nif $msg contains 'SECRET' then /var/log/cron.log\n", nil, 0, true, true},
		{"nested", "$IncludeConfig /etc/rsyslog.d/*.conf\n", map[string]string{"10-child.conf": "$IncludeConfig /etc/rsyslog.d/*.conf\n"}, 0, false, true},
		{"duplicate-prefix", "$IncludeConfig /etc/rsyslog.d/*.conf\n", map[string]string{"10-a.conf": "cron.* /var/log/cron.log\n", "10-b.conf": "cron.* ~\n"}, 0, false, true},
		{"unknown-name", "$IncludeConfig /etc/rsyslog.d/*.conf\n", map[string]string{"route.conf": "cron.* /var/log/cron.log\n"}, 0, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := rsyslogFixture(t, c.main, c.includes)
			r := rsyslogCronWithin(rsyslogCronSpec(), root, rsyslogProbe)
			if r.Error != c.error || r.Passed != (!c.error && c.input && c.mask == 255) || !c.error && !strings.Contains(r.Actual, fmt.Sprintf("covered_mask=0x%02x", c.mask)) || strings.Contains(r.Actual+r.Message, "SECRET") {
				t.Fatalf("wrong graph result %+v", r)
			}
		})
	}
}

func TestRsyslogCronRefusesUnsafeOrAmbiguousInputs(t *testing.T) {
	valid := "module(load=\"imuxsock\")\ncron.* /var/log/cron.log\n"
	for _, line := range []string{
		"cron.* @remote", "cron.* ^/tmp/script", "cron.* ?Dynamic", "cron.* /var/log/cron.log;custom",
		"cron.* /var/log/cron.log # comment", "cron.* /dev/null", "cron.* /var/log/../secret", "& /var/log/cron.log",
		"module(load=\"imtcp\")", "module(load=\"imuxsock\" SysSock.Name=\"/tmp/socket\")",
		"$ActionExecOnlyWhenPreviousIsSuspended on", "$ResetConfigVariables", "$IncludeConfig /tmp/*.conf",
		"$MainMsgQueueType Disk", "global(workDirectory=\"/tmp\")", "ruleset(name=\"custom\") {}", "cron.* /var/log/cron.log\x00",
		"$RepeatedMsgReduction on\n$RepeatedMsgReduction off", "module(load=\"imuxsock\")\nmodule(load=\"imuxsock\")",
	} {
		t.Run(line, func(t *testing.T) {
			root := rsyslogFixture(t, line+"\n"+valid, nil)
			if r := rsyslogCronWithin(rsyslogCronSpec(), root, rsyslogProbe); !r.Error || r.Passed {
				t.Fatalf("accepted %+v", r)
			}
		})
	}
	for _, kind := range []string{"missing", "symlink", "hardlink", "fifo", "writable", "access-acl", "default-acl", "too-large", "unterminated", "directory-entry", "too-many-files"} {
		t.Run(kind, func(t *testing.T) {
			root := rsyslogFixture(t, "module(load=\"imuxsock\")\n$IncludeConfig /etc/rsyslog.d/*.conf\n", map[string]string{"50-route.conf": "cron.* /var/log/cron.log\n"})
			path := filepath.Join(root, "etc/rsyslog.d/50-route.conf")
			var err error
			switch kind {
			case "missing":
				err = os.Remove(filepath.Join(root, "etc/rsyslog.conf"))
			case "symlink":
				err = os.Rename(path, path+".original")
				if err == nil {
					err = os.Symlink(path+".original", path)
				}
			case "hardlink":
				err = os.Link(path, path+".alias")
			case "fifo":
				err = os.Remove(path)
				if err == nil {
					err = unix.Mkfifo(path, 0600)
				}
			case "writable":
				err = os.Chmod(path, 0666)
			case "access-acl":
				err = unix.Setxattr(path, "system.posix_acl_access", logACL(), 0)
			case "default-acl":
				err = unix.Setxattr(filepath.Dir(path), "system.posix_acl_default", logACL(), 0)
			case "too-large":
				err = os.WriteFile(path, []byte(strings.Repeat("#", 64*1024)+"\n"), 0644)
			case "unterminated":
				err = os.WriteFile(path, []byte("cron.* /var/log/cron.log"), 0644)
			case "directory-entry":
				err = os.Remove(path)
				if err == nil {
					err = os.Mkdir(path, 0755)
				}
			case "too-many-files":
				for i := 0; i < 33; i++ {
					err = os.WriteFile(filepath.Join(filepath.Dir(path), fmt.Sprintf("%02d-fixture.conf", i)), []byte("#empty\n"), 0644)
					if err != nil {
						break
					}
				}
			}
			if err != nil {
				if (kind == "access-acl" || kind == "default-acl") && (err == unix.EINVAL || err == unix.EOPNOTSUPP) {
					t.Skip("local filesystem cannot create ACL fixture; mandatory native container covers it")
				}
				t.Fatal(err)
			}
			if r := rsyslogCronWithin(rsyslogCronSpec(), root, rsyslogProbe); !r.Error || r.Passed {
				t.Fatalf("accepted boundary %+v", r)
			}
		})
	}
}

func TestRsyslogCronChangesAndOneDeadline(t *testing.T) {
	for _, kind := range []string{"content", "replacement", "directory", "package", "timeout"} {
		t.Run(kind, func(t *testing.T) {
			root := rsyslogFixture(t, "module(load=\"imuxsock\")\n$IncludeConfig /etc/rsyslog.d/*.conf\n", map[string]string{"50-route.conf": "cron.* /var/log/cron.log\n"})
			calls := 0
			probe := func(ctx context.Context, _ int) ItemResult {
				calls++
				if calls == 2 {
					path := filepath.Join(root, "etc/rsyslog.d/50-route.conf")
					switch kind {
					case "content":
						if err := os.WriteFile(path, []byte("cron.* ~\n"), 0644); err != nil {
							t.Fatal(err)
						}
					case "replacement":
						if err := os.Rename(path, path+".backup"); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(path, []byte("cron.* /var/log/cron.log\n"), 0644); err != nil {
							t.Fatal(err)
						}
					case "directory":
						if err := os.WriteFile(filepath.Join(filepath.Dir(path), "10-drop.conf"), []byte("cron.* ~\n"), 0644); err != nil {
							t.Fatal(err)
						}
					case "package":
						return ItemResult{Error: true, Message: "package changed"}
					case "timeout":
						<-ctx.Done()
					}
				}
				return rsyslogProbe(ctx, 0)
			}
			cs := rsyslogCronSpec()
			cs.TimeoutMs = 100
			start := time.Now()
			r := rsyslogCronWithin(cs, root, probe)
			if !r.Error || r.Passed || time.Since(start) > time.Second {
				t.Fatalf("change/deadline accepted %+v", r)
			}
		})
	}
}
