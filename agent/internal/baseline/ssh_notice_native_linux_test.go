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

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func TestNativeSSHNotice(t *testing.T) {
	if os.Getenv("ALINKSEC_SSH_NOTICE_NATIVE_REQUIRED") != "true" {
		t.Skip("explicit isolated native runner fixture only")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required for mandatory trust/ACL fixtures")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/dpkg-query", "--show", "--showformat=${Version}", "openssh-server")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	version, err := cmd.Output()
	if err != nil || !sshNoticeVersion.Match(version) {
		t.Fatalf("exact Ubuntu24 OpenSSH required: %v version=%q", err, version)
	}
	raw, err := os.ReadFile("../../../deploy/baseline/packages/ssh-notice/linux-baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Items []struct{ Check json.RawMessage }
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Items) != 2 {
		t.Fatal("two-item candidate required")
	}
	checks := map[string]CheckSpec{}
	for _, item := range doc.Items {
		s, err := ParseCheck(string(item.Check))
		if err != nil {
			t.Fatal(err)
		}
		checks[s.Option] = *s
	}
	fixture := func(t *testing.T, body string) (sshNoticePaths, string) {
		t.Helper()
		_, paths := noticeFixture(t)
		key := filepath.Join(filepath.Dir(paths.directory), "hostkey")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("fixture key failed: %v %s", err, output)
		}
		config := filepath.Join(paths.directory, "sshd_config")
		noticeWrite(t, config, "HostKey "+key+"\n"+strings.ReplaceAll(body, "BANNER", paths.banner))
		return paths, config
	}
	check := func(t *testing.T, paths sshNoticePaths, option, address string, passed, executionError bool) {
		t.Helper()
		s := checks[option]
		connection := *s.Connection
		s.Connection = &connection
		s.Connection.Address = address
		result := noticeRun(s, paths, func(ctx context.Context, config string, connection *SSHConnection, timeout int) ItemResult {
			result := querySSHConfiguration(ctx, config, connection, timeout)
			if result.Error {
				// Only isolated fixture diagnostics are logged; production errors
				// remain redacted by sshNoticeWithin.
				t.Logf("native isolated SSH parser diagnostic: %+v", result)
			}
			return result
		})
		if result.Passed != passed || result.Error != executionError {
			t.Fatalf("native %s %s: %+v", option, address, result)
		}
		t.Logf("native SSH notice evidence: option=%s addr=%s passed=%t error=%t actual=%s message=%s", option, address, result.Passed, result.Error, result.Actual, result.Message)
	}
	t.Run("default_no_dns_and_no_banner", func(t *testing.T) {
		paths, _ := fixture(t, "# Native defaults are intentionally observed\n")
		check(t, paths, "usedns", "192.0.2.10", true, false)
		check(t, paths, "banner", "192.0.2.10", false, false)
	})
	t.Run("ordered_include_and_first_value", func(t *testing.T) {
		paths, config := fixture(t, "UseDNS no\nBanner none\n")
		dir := filepath.Join(paths.directory, "parts")
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		noticeWrite(t, filepath.Join(dir, "00-first.conf"), "UseDNS yes\nBanner "+paths.banner+"\n")
		noticeWrite(t, filepath.Join(dir, "10-later.conf"), "UseDNS no\nBanner none\n")
		current, err := os.ReadFile(config)
		if err != nil {
			t.Fatal(err)
		}
		noticeWrite(t, config, "Include "+dir+"/*.conf\n"+string(current))
		check(t, paths, "usedns", "192.0.2.10", false, false)
		check(t, paths, "banner", "192.0.2.10", true, false)
	})
	t.Run("match_address_and_connection_isolation", func(t *testing.T) {
		paths, config := fixture(t, "UseDNS no\nBanner none\nMatch User root Address 192.0.2.10\n Include match.conf\n")
		noticeWrite(t, filepath.Join(paths.directory, "match.conf"), "Banner "+paths.banner+"\n")
		// Relative Include paths are based on /etc/ssh in native OpenSSH.
		// The fixture uses absolute paths to keep all files isolated.
		data, err := os.ReadFile(config)
		if err != nil {
			t.Fatal(err)
		}
		noticeWrite(t, config, strings.ReplaceAll(string(data), "Include match.conf", "Include "+filepath.Join(paths.directory, "match.conf")))
		check(t, paths, "banner", "192.0.2.10", true, false)
		check(t, paths, "banner", "198.51.100.10", false, false)
	})
	t.Run("synthetic_host_is_not_name_resolution_evidence", func(t *testing.T) {
		paths, _ := fixture(t, "UseDNS no\nBanner none\nMatch Host admin.example.invalid\n Banner BANNER\n")
		check(t, paths, "banner", "192.0.2.10", true, false)
	})
	t.Run("native_parse_errors_and_body_mismatch", func(t *testing.T) {
		paths, _ := fixture(t, "UseDNS no\nBanner BANNER\n")
		noticeWrite(t, paths.banner, "Different reviewed text.\n")
		check(t, paths, "banner", "192.0.2.10", false, false)
		if err := os.Remove(paths.banner); err != nil {
			t.Fatal(err)
		}
		check(t, paths, "banner", "192.0.2.10", false, true)
		paths, _ = fixture(t, "UnknownDirective invalid\n")
		check(t, paths, "usedns", "192.0.2.10", false, true)
	})
	t.Run("mandatory_trust_limits_changes_and_deadline", func(t *testing.T) {
		t.Run("unsafe_inputs", TestSSHNoticeUnsafeInputs)
		t.Run("finite_include", TestSSHNoticeFiniteIncludeBoundaries)
		t.Run("total_bytes", TestSSHNoticeTotalBytesIncludesCRLFAndBanner)
		t.Run("changes_and_deadline", TestSSHNoticeChangesAndOneDeadline)
	})
	// The actual fixed production selector is only observed. Nothing modifies
	// the runner's SSH files, listener, banner or service.
	result := checkOne(&pb.BaselineCheckSpec{ItemId: "ssh-notice-product", Check: noticeJSON(checks["usedns"])})
	if result.ItemID != "ssh-notice-product" {
		t.Fatal("dispatcher lost item identity")
	}
	t.Logf("native SSH notice read-only product observation: item=%s passed=%t error=%t actual=%s message=%s", result.ItemID, result.Passed, result.Error, result.Actual, result.Message)
	t.Log("Native SSH notice declarations: product=" + string(version) + " scenarios=6 native_comparisons=10 mandatory_boundaries_executed=true")
}
