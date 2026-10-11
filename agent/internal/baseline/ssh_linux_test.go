//go:build linux

package baseline

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func sshTestSpec(target string) CheckSpec {
	return CheckSpec{Type: "sshd_effective", Target: target, Option: "permitrootlogin", Operator: "eq", Expected: "no", TimeoutMs: 1000,
		Connection: &SSHConnection{User: "root", Host: "admin.example.invalid", Address: "192.0.2.10", LocalAddress: "192.0.2.20", LocalPort: 22}}
}

func TestSSHParserRequiresExplicitSafeConnection(t *testing.T) {
	valid := sshTestSpec("/etc/ssh/sshd_config")
	for _, change := range []func(*CheckSpec){
		func(s *CheckSpec) { s.Connection = nil },
		func(s *CheckSpec) { s.Connection.User = "root,addr=198.51.100.1" },
		func(s *CheckSpec) { s.Connection.User = "other" },
		func(s *CheckSpec) { s.Connection.Host = "localhost;touch /tmp/injected" },
		func(s *CheckSpec) { s.Connection.Address = "example.org" },
		func(s *CheckSpec) { s.Connection.Address = "127.000.0.1" },
		func(s *CheckSpec) { s.Connection.LocalAddress = "fe80::1%eth0" },
		func(s *CheckSpec) { s.Connection.LocalAddress = "::ffff:192.0.2.1" },
		func(s *CheckSpec) { s.Connection.LocalPort = 0 },
		func(s *CheckSpec) { s.Connection.LocalPort = 65536 },
		func(s *CheckSpec) { s.Option = "authorizedkeyscommand" },
		func(s *CheckSpec) { s.Cmd = "echo injected" },
		func(s *CheckSpec) { s.Target = "relative" },
		func(s *CheckSpec) { s.Operator = "not_contains" },
		func(s *CheckSpec) { s.Expected = "" },
	} {
		copy := valid
		connection := *valid.Connection
		copy.Connection = &connection
		change(&copy)
		data, _ := json.Marshal(copy)
		if _, err := ParseCheck(string(data)); err == nil {
			t.Fatalf("accepted unsafe check: %s", data)
		}
	}
	data, _ := json.Marshal(valid)
	if _, err := ParseCheck(string(data)); err != nil {
		t.Fatalf("valid check rejected: %v", err)
	}
	duplicate := strings.Replace(string(data), `"user":"root"`, `"user":"wrong","user":"root"`, 1)
	if _, err := ParseCheck(duplicate); err == nil {
		t.Fatal("duplicate connection key accepted")
	}
	unknown := strings.Replace(string(data), `"user":"root"`, `"extra":"flag","user":"root"`, 1)
	if _, err := ParseCheck(unknown); err == nil {
		t.Fatal("unknown connection key accepted")
	}
	for _, address := range []string{"192.0.2.10", "2001:db8::10"} {
		valid.Connection.Address, valid.Connection.LocalAddress = address, address
		data, _ := json.Marshal(valid)
		if _, err := ParseCheck(string(data)); err != nil {
			t.Fatalf("literal %s rejected: %v", address, err)
		}
	}
}

func TestNativeSSHEffectiveConfiguration(t *testing.T) {
	if _, err := os.Stat("/usr/sbin/sshd"); err != nil {
		if os.Getenv("ALINKSEC_SSH_NATIVE_REQUIRED") == "true" {
			t.Fatal(err)
		}
		t.Skip("OpenSSH server is not installed")
	}
	root := t.TempDir()
	key := filepath.Join(root, "hostkey")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("fixture host key: %v: %s", err, output)
	}
	write := func(name, contents string) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	defaults := write("defaults.conf", "# PermitRootLogin no\nPermitRootLogin prohibit-password\nMaxAuthTries 4\n")
	match := write("root.conf", "PermitRootLogin no\nMaxAuthTries 3\n")
	config := write("sshd_config", "HostKey "+key+"\nInclude "+defaults+"\nPermitRootLogin yes\nMaxAuthTries 6\nMatch User root Address 192.0.2.10\n Include "+match+"\n PermitRootLogin yes\n MaxAuthTries 8\n")
	raw, err := os.ReadFile("../../../deploy/baseline/packages/ssh/linux-baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	var candidate struct {
		Items []struct{ Check json.RawMessage }
	}
	if err := json.Unmarshal(raw, &candidate); err != nil {
		t.Fatal(err)
	}
	checks := map[string]*CheckSpec{}
	for _, item := range candidate.Items {
		check, err := ParseCheck(string(item.Check))
		if err != nil {
			t.Fatal(err)
		}
		checks[check.Option] = check
	}
	if len(checks) != 2 || checks["permitrootlogin"] == nil || checks["maxauthtries"] == nil {
		t.Fatal("candidate must provide both native SSH queries")
	}
	for _, tc := range []struct {
		address, rootValue, tries string
		rootPass                  bool
	}{
		{"192.0.2.10", "no", "3", true}, {"198.51.100.10", "prohibit-password", "4", false},
	} {
		t.Run(tc.address, func(t *testing.T) {
			spec := *checks["permitrootlogin"]
			connection := *spec.Connection
			spec.Connection = &connection
			spec.Target = config
			spec.Connection.Address = tc.address
			result := checkSSHEffective(&spec)
			// Older OpenSSH prints the deprecated synonym without-password.
			// Both spellings prohibit passwords but still permit other root auth.
			rootMatches := strings.HasSuffix(result.Actual, "permitrootlogin="+tc.rootValue) ||
				tc.rootValue == "prohibit-password" && strings.HasSuffix(result.Actual, "permitrootlogin=without-password")
			if result.Error || result.Passed != tc.rootPass || !rootMatches || !strings.Contains(result.Actual, "addr="+tc.address) {
				t.Fatalf("Include/duplicate/Match result: %+v", result)
			}
			t.Logf("native SSH configuration evidence (isolated fixture): %s", result.Actual)
			spec = *checks["maxauthtries"]
			connection = *spec.Connection
			spec.Connection = &connection
			spec.Connection.Address = tc.address
			spec.Target = config
			result = checkSSHEffective(&spec)
			if result.Error || !result.Passed || !strings.Contains(result.Actual, "maxauthtries="+tc.tries) {
				t.Fatalf("attempt limit: %+v", result)
			}
			t.Logf("native SSH configuration evidence (isolated fixture): %s", result.Actual)
		})
	}
	for _, path := range []string{write("invalid.conf", "UnknownDirective broken\n"), filepath.Join(root, "missing.conf"), root} {
		spec := sshTestSpec(path)
		result := checkSSHEffective(&spec)
		if !result.Error || result.Passed {
			t.Fatalf("invalid/missing/non-file config must preserve error: %+v", result)
		}
	}
	fifo := filepath.Join(root, "blocked-include.conf")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	spec := sshTestSpec(write("blocked.conf", "HostKey "+key+"\nInclude "+fifo+"\n"))
	spec.TimeoutMs = 100
	start := time.Now()
	result := checkSSHEffective(&spec)
	if !result.Error || result.Passed || !strings.Contains(result.Message, "超时") || time.Since(start) > 2*time.Second {
		t.Fatalf("blocked Include must time out: %+v", result)
	}
}
