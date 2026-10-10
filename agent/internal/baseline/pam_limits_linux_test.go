//go:build linux

package baseline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const pamLimitsChain = "session required pam_limits.so\nsession required pam_unix.so\n"
const pamLimitsConfig = "* - core 0\nroot - core 0\n* - nofile 4096\nroot - nofile 4096\n* - nproc 256\nroot - nproc 256\n"

func pamLimitsSpec(option string) *CheckSpec {
	return &CheckSpec{Type: "pam_limits", Target: "/etc/pam.d/login", Option: option, Operator: "eq", Expected: pamLimitsReference(option), TimeoutMs: 1000}
}
func pamLimitsFixture(t *testing.T) pamLimitsPaths {
	t.Helper()
	root := t.TempDir()
	p := pamLimitsPaths{directory: filepath.Join(root, "pam.d"), security: filepath.Join(root, "security"), modules: filepath.Join(root, "modules"), uid: uint32(os.Geteuid()), gid: uint32(os.Getegid())}
	for _, dir := range []string{p.directory, p.security, p.security + "/limits.d", p.modules} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	pamWrite(t, p.directory+"/login", "session include common-session\n")
	pamWrite(t, p.directory+"/common-session", pamLimitsChain)
	pamWrite(t, p.security+"/limits.conf", pamLimitsConfig)
	for _, module := range []string{"pam_limits.so", "pam_unix.so", "pam_permit.so"} {
		pamWrite(t, p.modules+"/"+module, "isolated presence fixture")
	}
	return p
}
func limitsResult(t *testing.T, p pamLimitsPaths, option string) ItemResult {
	t.Helper()
	r := pamLimitsWithin(pamLimitsSpec(option), p, time.Now().Add(time.Second))
	if strings.Contains(r.Actual+r.Message, "DO_NOT_REPORT_PAM_SECRET") {
		t.Fatal("unreviewed policy value leaked")
	}
	return r
}
func TestPAMLimitsSharedPolicyAndNativeOrder(t *testing.T) {
	p := pamLimitsFixture(t)
	for _, option := range []string{"core", "nofile", "nproc"} {
		if r := limitsResult(t, p, option); r.Error || !r.Passed {
			t.Fatalf("initial %s: %+v", option, r)
		}
	}
	pamWrite(t, p.security+"/limits.d/10-base.conf", "* hard nofile 8192\nroot hard nofile 8192\n")
	pamWrite(t, p.security+"/limits.d/90-final.conf", "* soft nofile 12000\nroot soft nofile 12000\n")
	pamWrite(t, p.security+"/limits.d/.hidden.conf", "DO_NOT_REPORT_PAM_SECRET\n")
	pamWrite(t, p.security+"/limits.d/ignored.conf.backup", "DO_NOT_REPORT_PAM_SECRET\n")
	r := limitsResult(t, p, "nofile")
	if r.Error || !r.Passed || !strings.Contains(r.Actual, "default_declared_soft=12000 default_declared_hard=8192 default_normalized_soft=8192") {
		t.Fatalf("native soft clamp and order: %+v", r)
	}
	pamWrite(t, p.security+"/limits.d/zz-backup.conf.backup.conf", "* hard nofile 99999\n")
	if r := limitsResult(t, p, "nofile"); r.Error || r.Passed {
		t.Fatalf("all matching conf entries must count: %+v", r)
	}
}
func TestPAMLimitsFailuresStaySeparateAcrossResources(t *testing.T) {
	for _, scenario := range []struct{ policy, option string }{
		{strings.ReplaceAll(pamLimitsConfig, "* - core 0", "* - core 1"), "core"},
		{pamLimitsConfig + "root hard nofile 512\n", "nofile"},
		{pamLimitsConfig + "* - nproc unlimited\n", "nproc"},
		{pamLimitsConfig + "* soft core unlimited\n", "core"},
		{strings.ReplaceAll(pamLimitsConfig, "root - core 0\n", ""), "core"},
		{strings.ReplaceAll(pamLimitsConfig, "* - nofile 4096", "* soft nofile 4096"), "nofile"},
	} {
		p := pamLimitsFixture(t)
		pamWrite(t, p.security+"/limits.conf", scenario.policy)
		if r := limitsResult(t, p, scenario.option); r.Error || r.Passed {
			t.Fatalf("known policy mismatch: %+v", r)
		}
	}
	p := pamLimitsFixture(t)
	pamWrite(t, p.directory+"/common-session", "session required pam_unix.so\n")
	if r := limitsResult(t, p, "core"); r.Error || r.Passed {
		t.Fatalf("missing mandatory module: %+v", r)
	}
	pamWrite(t, p.directory+"/common-session", pamLimitsChain)
	pamWrite(t, p.security+"/limits.conf", pamLimitsConfig+"* - nproc 5000\n")
	for _, option := range []string{"core", "nofile"} {
		if r := limitsResult(t, p, option); r.Error || !r.Passed {
			t.Fatalf("independent result %s: %+v", option, r)
		}
	}
}
func TestPAMLimitsUnknownInputsAndSessionBypassesAreErrors(t *testing.T) {
	for _, extra := range []string{"root -\n", "@admins - core 0\n", "alice hard nofile 4000\n", ":1000 - nproc 256\n", "* - nofile 123x\n", "* - core 18446744073709551616\n", "* - memlock 32\n", "* - core 0 extra\n", strings.Repeat("#", 1023) + "\n", "* - core DO_NOT_REPORT_PAM_SECRET\n"} {
		p := pamLimitsFixture(t)
		pamWrite(t, p.security+"/limits.conf", pamLimitsConfig+extra)
		if r := limitsResult(t, p, "core"); !r.Error || r.Passed {
			t.Fatalf("unknown policy accepted: %+v", r)
		}
	}
	for _, chain := range []string{"session sufficient pam_permit.so\n" + pamLimitsChain, strings.ReplaceAll(pamLimitsChain, "required pam_limits", "optional pam_limits"), "session required pam_limits.so conf=/tmp/policy\n", "session required pam_limits.so set_all\n", pamLimitsChain + pamLimitsChain, "session [success=1 default=ignore] pam_limits.so\n", "session required pam_systemd.so\n", "session substack common-session\n", "@include login\n"} {
		p := pamLimitsFixture(t)
		pamWrite(t, p.directory+"/common-session", chain)
		if r := limitsResult(t, p, "core"); !r.Error || r.Passed {
			t.Fatalf("unsupported chain: %+v", r)
		}
	}
}
func TestPAMLimitsUnsafeFilesystemAndDeadline(t *testing.T) {
	for _, kind := range []string{"link", "fifo", "directory", "hardlink", "writable", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			p := pamLimitsFixture(t)
			path := p.security + "/limits.d/10-policy.conf"
			switch kind {
			case "link":
				if err := os.Symlink(p.security+"/limits.conf", path); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(p.security+"/limits.conf", path); err != nil {
					t.Fatal(err)
				}
			case "writable":
				pamWrite(t, path, "# policy\n")
				if err := os.Chmod(path, 0666); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				pamWrite(t, path, strings.Repeat("#", 64*1024+1))
			}
			if r := limitsResult(t, p, "core"); !r.Error || r.Passed {
				t.Fatalf("unsafe input accepted: %+v", r)
			}
		})
	}
	p := pamLimitsFixture(t)
	if r := pamLimitsWithin(pamLimitsSpec("core"), p, time.Now().Add(-time.Second)); !r.Error {
		t.Fatal("expired shared deadline accepted")
	}
	r := newPAMRead(1000)
	defer r.close()
	if _, err := readPAMLimitsPolicy(r, p.security); err != nil {
		t.Fatal(err)
	}
	pamWrite(t, p.security+"/limits.d/created.conf", "* - core 1\n")
	if err := r.stable(); err == nil {
		t.Fatal("changed drop-in membership accepted")
	}
}
