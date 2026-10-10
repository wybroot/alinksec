//go:build linux

package baseline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const pamWriter = "password [success=1 default=ignore] pam_unix.so obscure yescrypt use_authtok\npassword requisite pam_deny.so\npassword required pam_permit.so\n"
const pamQuality = "password requisite pam_pwquality.so retry=1\n"
const pamPolicy = "minlen=12\nminclass=3\ndcredit=0\nucredit=0\nlcredit=0\nocredit=0\nenforcing=1\nenforce_for_root\n"

func pamFixture(t *testing.T) pamPaths {
	t.Helper()
	root := t.TempDir()
	paths := pamPaths{filepath.Join(root, "pam.d"), filepath.Join(root, "pwquality.conf"), filepath.Join(root, "modules")}
	for _, dir := range []string{paths.directory, paths.modules, paths.quality + ".d"} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	pamWrite(t, filepath.Join(paths.directory, "passwd"), "# chosen service\n@include common-password\n")
	pamWrite(t, filepath.Join(paths.directory, "common-password"), pamQuality+pamWriter)
	pamWrite(t, paths.quality, pamPolicy)
	for _, name := range []string{"pam_pwquality.so", "pam_unix.so", "pam_deny.so", "pam_permit.so"} {
		pamWrite(t, filepath.Join(paths.modules, name), "isolated module presence fixture\n")
	}
	return paths
}
func pamWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}
func pamSpec(option string) *CheckSpec {
	expected := pamQualityReference
	if option == "unix_hash" {
		expected = "yescrypt"
	}
	return &CheckSpec{Type: "pam_password", Target: "/etc/pam.d/passwd", Option: option, Operator: "eq", Expected: expected, TimeoutMs: 1000}
}
func pamResult(t *testing.T, paths pamPaths, option string) ItemResult {
	t.Helper()
	result := pamPasswordWithin(pamSpec(option), paths)
	if strings.Contains(result.Actual+result.Message, "DO_NOT_REPORT_PAM_SECRET") {
		t.Fatal("unreviewed configuration value escaped into evidence")
	}
	return result
}
func TestPAMPasswordExpandsIncludesAndHonorsNativeConfigurationOrder(t *testing.T) {
	paths := pamFixture(t)
	pamWrite(t, filepath.Join(paths.directory, "passwd"), "password include first\n")
	pamWrite(t, filepath.Join(paths.directory, "first"), "@include common-password\n")
	pamWrite(t, paths.quality+".d/10-policy.conf", "minlen=30\nminclass=4\n")
	pamWrite(t, paths.quality+".d/90-policy.conf", "minlen=26\n")
	pamWrite(t, paths.quality+".d/ignored.conf.backup.conf", "minlen=1\nenforcing=0\n")
	for _, option := range []string{"quality", "unix_hash"} {
		if result := pamResult(t, paths, option); result.Error || !result.Passed {
			t.Fatalf("main file overrides drop-ins: %+v", result)
		}
	}
	pamWrite(t, filepath.Join(paths.directory, "common-password"), "PASSWORD requisite pam_pwquality.so \\\n minlen=16 minclass=4 enforcing=0\n"+pamWriter)
	result := pamResult(t, paths, "quality")
	if result.Error || result.Passed || !strings.Contains(result.Actual, "minlen=16 minclass=4") || !strings.Contains(result.Actual, "enforcing=0") {
		t.Fatalf("module overrides lost: %+v", result)
	}
	pamWrite(t, filepath.Join(paths.directory, "common-password"), pamQuality+pamWriter)
	pamWrite(t, paths.quality, pamPolicy+"enforce_for_root=0\n")
	if result := pamResult(t, paths, "quality"); result.Error || !result.Passed {
		t.Fatalf("native SET flag semantics lost: %+v", result)
	}
}
func TestPAMPasswordSeparatesKnownPolicyFailuresFromUnconfirmedChains(t *testing.T) {
	for _, change := range []string{"minlen=8\n", "minclass=1\n", "dcredit=1\n", "ucredit=1\n", "lcredit=1\n", "ocredit=1\n", "enforcing=0\n"} {
		paths := pamFixture(t)
		pamWrite(t, paths.quality, pamPolicy+change)
		if result := pamResult(t, paths, "quality"); result.Error || result.Passed {
			t.Fatalf("reference mismatch %s: %+v", change, result)
		}
	}
	paths := pamFixture(t)
	pamWrite(t, paths.quality, strings.ReplaceAll(pamPolicy, "enforce_for_root\n", ""))
	if result := pamResult(t, paths, "quality"); result.Error || result.Passed {
		t.Fatalf("root exception passed: %+v", result)
	}
	pamWrite(t, filepath.Join(paths.directory, "common-password"), strings.ReplaceAll(pamWriter, " use_authtok", ""))
	if result := pamResult(t, paths, "quality"); result.Error || result.Passed {
		t.Fatalf("missing quality module passed: %+v", result)
	}
	if result := pamResult(t, paths, "unix_hash"); result.Error || !result.Passed {
		t.Fatalf("declared hash selection: %+v", result)
	}
	pamWrite(t, filepath.Join(paths.directory, "common-password"), pamQuality+strings.ReplaceAll(pamWriter, " use_authtok", ""))
	if result := pamResult(t, paths, "quality"); result.Error || result.Passed {
		t.Fatalf("unbound token passed: %+v", result)
	}
	pamWrite(t, filepath.Join(paths.directory, "common-password"), pamQuality+strings.ReplaceAll(pamWriter, "yescrypt", "sha512"))
	if result := pamResult(t, paths, "unix_hash"); result.Error || result.Passed {
		t.Fatalf("wrong hash passed: %+v", result)
	}
	for _, chain := range []string{
		"password sufficient pam_permit.so\n" + pamQuality + pamWriter,
		strings.Replace(pamQuality+pamWriter, "requisite pam_pwquality", "optional pam_pwquality", 1),
		strings.Replace(pamQuality+pamWriter, "success=1", "success=2", 1),
		pamWriter + pamQuality,
		strings.Replace(pamWriter, "pam_unix.so", "pam_sss.so", 1),
		"password substack common-password\n",
		"@include passwd\n",
		"@include ../outside\n",
		"@include missing\n",
		strings.Replace(pamWriter, "yescrypt", "yescrypt md5", 1),
		strings.Replace(pamWriter, "yescrypt", "", 1),
	} {
		paths := pamFixture(t)
		pamWrite(t, filepath.Join(paths.directory, "passwd"), chain)
		if result := pamResult(t, paths, "unix_hash"); !result.Error || result.Passed {
			t.Fatalf("unconfirmed chain accepted: %+v", result)
		}
	}
}
func TestPAMPasswordRejectsUnsafeInputsChangesAndBrokenOptions(t *testing.T) {
	for _, change := range []string{"minlen=garbage_DO_NOT_REPORT_PAM_SECRET\n", "unknown=DO_NOT_REPORT_PAM_SECRET\n", "minclass=2147483647\n", strings.Repeat("x", 1024) + "\n", "local_users_only=0\n"} {
		paths := pamFixture(t)
		pamWrite(t, paths.quality, pamPolicy+change)
		if result := pamResult(t, paths, "quality"); !result.Error || result.Passed {
			t.Fatalf("broken config accepted: %+v", result)
		}
	}
	for _, kind := range []string{"symlink", "fifo", "directory", "oversized", "missing-module"} {
		t.Run(kind, func(t *testing.T) {
			paths := pamFixture(t)
			path := paths.quality
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				if err := os.Symlink(filepath.Join(paths.directory, "passwd"), path); err != nil {
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
			case "oversized":
				pamWrite(t, path, strings.Repeat("#", 64*1024+1))
			case "missing-module":
				pamWrite(t, path, pamPolicy)
				os.Remove(filepath.Join(paths.modules, "pam_unix.so"))
			}
			if result := pamResult(t, paths, "quality"); !result.Error || result.Passed {
				t.Fatalf("unsafe input accepted: %+v", result)
			}
		})
	}
	paths := pamFixture(t)
	r := newPAMRead(1000)
	defer r.close()
	if _, err := r.lines(paths.quality); err != nil {
		t.Fatal(err)
	}
	pamWrite(t, paths.quality, pamPolicy+"minlen=8\n")
	if r.stable() == nil {
		t.Fatal("changed input accepted")
	}
	r2 := newPAMRead(1000)
	defer r2.close()
	os.RemoveAll(paths.quality + ".d")
	r2.absent = append(r2.absent, paths.quality+".d")
	os.Mkdir(paths.quality+".d", 0700)
	if r2.stable() == nil {
		t.Fatal("created absent drop-in directory accepted")
	}
}
