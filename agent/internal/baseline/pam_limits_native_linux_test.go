//go:build linux

package baseline

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativePAMLimits(t *testing.T) {
	if os.Getenv("ALINKSEC_PAM_ISOLATED_REQUIRED") != "true" {
		t.Skip("dedicated disposable PAM image required")
	}
	marker, err := os.ReadFile("/usr/local/lib/alinksec-pam-fixture")
	if err != nil || string(marker) != "isolated-pam-fixture-v1\n" || os.Geteuid() != 0 {
		t.Fatal("refuse session changes outside dedicated fixture")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("dedicated container required")
	}
	version, err := exec.Command("/usr/bin/dpkg-query", "--show", "--showformat=${Version}", "libpam-modules").Output()
	if err != nil || !pamLimitsVersion.MatchString(string(version)) {
		t.Fatal("exact Ubuntu24 PAM package required")
	}
	raw, err := os.ReadFile("../../../deploy/baseline/packages/pam-limits/linux-baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Items []struct{ Check json.RawMessage }
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Items) != 3 {
		t.Fatal("shipped three-item resource candidate required")
	}
	specs := map[string]*CheckSpec{}
	for _, item := range doc.Items {
		s, err := ParseCheck(string(item.Check))
		if err != nil {
			t.Fatal(err)
		}
		specs[s.Option] = s
	}
	paths := systemPAMLimitsPaths()
	// Only the disposable image is modified; never a host PAM mount.
	entries, err := os.ReadDir(paths.security + "/limits.d")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(paths.security, "limits.d", entry.Name())); err != nil {
			t.Fatal(err)
		}
	}
	configure := func(chain, policy string) {
		t.Helper()
		pamWrite(t, paths.directory+"/login", "session include alinksec-limits\n")
		pamWrite(t, paths.directory+"/alinksec-limits", chain)
		pamWrite(t, paths.security+"/limits.conf", policy)
	}
	probe := func(user, mode string) map[string]any {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "/usr/local/bin/alinksec-pam-limits-probe", user, mode).Output()
		if err != nil {
			t.Fatalf("isolated session probe failed: %v", err)
		}
		var values map[string]any
		if json.Unmarshal(out, &values) != nil {
			t.Fatal("invalid public session probe outcome")
		}
		return values
	}
	check := func(option string, pass, executionError bool) ItemResult {
		t.Helper()
		r := checkPAMLimits(specs[option])
		if r.Passed != pass || r.Error != executionError {
			t.Fatalf("%s shipped observation: %+v", option, r)
		}
		return r
	}
	assertValue := func(values map[string]any, key string, want any) {
		t.Helper()
		if values[key] != want {
			t.Fatalf("public probe %s: got %v want %v", key, values[key], want)
		}
	}
	t.Run("all three resources in real sessions", func(t *testing.T) {
		configure(pamLimitsChain, pamLimitsConfig)
		for _, option := range []string{"core", "nofile", "nproc"} {
			r := check(option, true, false)
			t.Logf("native PAM limits evidence: baseline %s; %s", option, r.Actual)
		}
		for _, user := range []string{"root", "alinksec-pam-test"} {
			v := probe(user, "observe")
			assertValue(v, "rc", float64(0))
			for key, value := range map[string]string{"core_soft": "0", "core_hard": "0", "nofile_soft": "4096", "nofile_hard": "4096", "nproc_soft": "256", "nproc_hard": "256"} {
				assertValue(v, key, value)
			}
		}
	})
	t.Run("dropin order root priority and soft clamp", func(t *testing.T) {
		configure(pamLimitsChain, pamLimitsConfig+"root soft nofile 12000\nroot hard nofile 8192\n")
		pamWrite(t, paths.security+"/limits.d/10-low.conf", "* - nofile 2048\n")
		pamWrite(t, paths.security+"/limits.d/90-high.conf", "* soft nofile 16000\n* hard nofile 4096\n")
		pamWrite(t, paths.security+"/limits.d/.ignored.conf", "* - nofile 100000\n")
		r := check("nofile", true, false)
		for user, value := range map[string]string{"root": "8192", "alinksec-pam-test": "4096"} {
			v := probe(user, "observe")
			assertValue(v, "rc", float64(0))
			assertValue(v, "nofile_soft", value)
			assertValue(v, "nofile_hard", value)
		}
		t.Logf("native PAM limits evidence: sorted dropins explicit root priority and soft clamp; %s", r.Actual)
		for _, name := range []string{"10-low.conf", "90-high.conf", ".ignored.conf"} {
			if err := os.Remove(paths.security + "/limits.d/" + name); err != nil {
				t.Fatal(err)
			}
		}
	})
	t.Run("soft hard and explicit root failures", func(t *testing.T) {
		configure(pamLimitsChain, pamLimitsConfig+"* hard nofile 512\n* - nproc 5000\nroot - core 4\n")
		for _, option := range []string{"core", "nofile", "nproc"} {
			check(option, false, false)
		}
		v := probe("alinksec-pam-test", "observe")
		assertValue(v, "rc", float64(0))
		assertValue(v, "nofile_soft", "512")
		assertValue(v, "nofile_hard", "512")
		assertValue(v, "nproc_hard", "5000")
		v = probe("root", "observe")
		assertValue(v, "rc", float64(0))
		assertValue(v, "core_hard", "4096")
		t.Log("native PAM limits evidence: independent noncompliance matches three actual rlimits")
	})
	t.Run("infinity declarations", func(t *testing.T) {
		configure(pamLimitsChain, pamLimitsConfig+"* - core -1\n* - nofile infinity\n* - nproc unlimited\n")
		for _, option := range []string{"core", "nofile", "nproc"} {
			check(option, false, false)
		}
		v := probe("alinksec-pam-test", "observe")
		assertValue(v, "rc", float64(0))
		assertValue(v, "core_hard", "unlimited")
		assertValue(v, "nproc_hard", "unlimited")
		nr, err := os.ReadFile("/proc/sys/fs/nr_open")
		if err != nil {
			t.Fatal(err)
		}
		assertValue(v, "nofile_hard", strings.TrimSpace(string(nr)))
		t.Log("native PAM limits evidence: core/nproc infinity and nofile nr_open are outside finite reference")
	})
	t.Run("unsupported bypass and explicit alternate config", func(t *testing.T) {
		configure("session sufficient pam_permit.so\n"+pamLimitsChain, pamLimitsConfig)
		check("core", false, true)
		v := probe("alinksec-pam-test", "observe")
		assertValue(v, "rc", float64(0))
		// conf= skips limits.d in PAM; production refuses that alternate scope.
		configure("session required pam_limits.so conf=/etc/security/limits.conf\n", pamLimitsConfig)
		pamWrite(t, paths.security+"/limits.d/90-skipped.conf", "* - nofile 32\n")
		check("nofile", false, true)
		v = probe("alinksec-pam-test", "observe")
		assertValue(v, "rc", float64(0))
		assertValue(v, "nofile_hard", "4096")
		if err := os.Remove(paths.security + "/limits.d/90-skipped.conf"); err != nil {
			t.Fatal(err)
		}
		t.Log("native PAM limits evidence: early session bypass and conf dropin exclusion remain errors")
	})
	t.Run("kernel enforcement ordinary and root exception", func(t *testing.T) {
		configure(pamLimitsChain, "* - core 0\nroot - core 0\n* - nofile 32\nroot - nofile 32\n* - nproc 2\nroot - nproc 2\n")
		check("core", true, false)
		check("nofile", false, false)
		check("nproc", true, false)
		v := probe("alinksec-pam-test", "enforce")
		assertValue(v, "rc", float64(0))
		assertValue(v, "fd_denied", true)
		assertValue(v, "fork_denied", true)
		v = probe("root", "enforce")
		assertValue(v, "rc", float64(0))
		assertValue(v, "fd_denied", true)
		assertValue(v, "fork_denied", false)
		assertValue(v, "children", float64(4))
		t.Log("native PAM limits evidence: ordinary file/fork denial; UID0 nproc enforcement exempt despite configured rlimit")
	})
}
