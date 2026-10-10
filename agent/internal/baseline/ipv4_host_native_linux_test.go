//go:build linux

package baseline

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"golang.org/x/sys/unix"
)

func TestNativeIPv4Host(t *testing.T) {
	if os.Getenv("ALINKSEC_IPV4_HOST_NATIVE_REQUIRED") != "true" {
		t.Skip("explicit disposable network namespace only")
	}
	marker, err := os.ReadFile("/usr/local/lib/alinksec-ipv4-host-fixture")
	if os.Geteuid() != 0 || os.Getenv("ALINKSEC_IPV4_HOST_ISOLATED_REQUIRED") != "true" || err != nil || string(marker) != "isolated-ipv4-host-fixture-v1\n" {
		t.Fatal("root, both switches and isolated image marker required")
	}
	if _, err := os.Lstat("/etc/alinksec"); !os.IsNotExist(err) {
		t.Fatal("refusing to replace existing role directory")
	}
	if err := os.Mkdir("/etc/alinksec", 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll("/etc/alinksec") })
	writeRole := func() {
		t.Helper()
		if err := os.WriteFile(ipv4HostRolePath, []byte(ipv4HostRole), 0644); err != nil {
			t.Fatal(err)
		}
	}
	writeRole()
	// A dotted name and an administratively down dummy are included. They inherit
	// default, so namespace defaults are tested against real newly created links.
	for _, name := range []string{"fixture0", "fixture0.42"} {
		cmd := exec.Command("/usr/sbin/ip", "link", "add", name, "type", "dummy")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatal(err, string(output))
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	values, err := readIPv4HostSnapshot(ctx, "/proc", true)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	if len(values.Interfaces) != 5 {
		t.Fatal("all/default and all three real interfaces required", values)
	}
	switch os.Getenv("ALINKSEC_IPV4_HOST_SCENARIO") {
	case "local-forward":
		if values.IPForward != 0 || values.Interfaces["lo"].Forwarding != 1 {
			t.Fatal("local forwarding fixture was reset", values)
		}
	case "future-forward":
		if values.IPForward != 0 || values.Interfaces["default"].Forwarding != 1 || values.Interfaces["fixture0.42"].Forwarding != 1 {
			t.Fatal("future forwarding fixture was reset", values)
		}
	case "loose-interface":
		if values.Interfaces["all"].RPFilter != 1 || values.Interfaces["lo"].RPFilter != 2 {
			t.Fatal("loose interface fixture missing", values)
		}
	}
	for option, env := range map[string]string{"rp_filter": "ALINKSEC_IPV4_HOST_RP_PASS", "forwarding": "ALINKSEC_IPV4_HOST_FORWARD_PASS"} {
		if os.Getenv(env) != "true" && os.Getenv(env) != "false" {
			t.Fatal("explicit expected native result required")
		}
		cs := ipv4HostSpec(option)
		cs.TimeoutMs = 5000
		result := checkOne(&pb.BaselineCheckSpec{ItemId: "native-ipv4-" + option, Check: ipv4HostJSON(cs)})
		if result.Error || result.Passed != (os.Getenv(env) == "true") || result.ItemID != "native-ipv4-"+option || !strings.Contains(result.Actual, "fixture0.42:") {
			t.Fatal(result)
		}
		// Independent native sysctl read uses slash paths to preserve dotted names.
		cmd := exec.Command("/usr/sbin/sysctl", "-n", "net/ipv4/conf/fixture0.42/rp_filter")
		output, err := cmd.Output()
		if err != nil || strings.TrimSpace(string(output)) != string(rune('0'+values.Interfaces["fixture0.42"].RPFilter)) {
			t.Fatal("native procps disagreement", err, string(output))
		}
		t.Logf("scenario=%s %s passed=%t actual=%s", os.Getenv("ALINKSEC_IPV4_HOST_SCENARIO"), option, result.Passed, result.Actual)
	}
	if os.Getenv("ALINKSEC_IPV4_HOST_SCENARIO") != "strict" {
		return
	}
	cs := ipv4HostSpec("rp_filter")
	errorRequired := func() {
		t.Helper()
		if r := checkIPv4Host(&cs); !r.Error || r.Passed {
			t.Fatal("unconfirmed role accepted", r)
		}
	}
	for _, body := range []string{"", "router\n", "unknown\n", "non-router-symmetric", "non-router-symmetric\nextra\n"} {
		if err := os.WriteFile(ipv4HostRolePath, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
		errorRequired()
	}
	writeRole()
	for _, mutate := range []func() error{func() error { return os.Chmod(ipv4HostRolePath, 0666) }, func() error { return os.Chown(ipv4HostRolePath, 65534, 0) }, func() error { return os.Chown(ipv4HostRolePath, 0, 65534) }, func() error { return unix.Setxattr(ipv4HostRolePath, "system.posix_acl_access", logACL(), 0) }} {
		if err := mutate(); err != nil {
			t.Fatal("mandatory role boundary unavailable", err)
		}
		errorRequired()
		os.Chown(ipv4HostRolePath, 0, 0)
		unix.Removexattr(ipv4HostRolePath, "system.posix_acl_access")
		os.Chmod(ipv4HostRolePath, 0644)
	}
	for _, attr := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		if err := unix.Setxattr("/etc/alinksec", attr, logACL(), 0); err != nil {
			t.Fatal(err)
		}
		errorRequired()
		if err := unix.Removexattr("/etc/alinksec", attr); err != nil {
			t.Fatal(err)
		}
		os.Chmod("/etc/alinksec", 0755)
	}
	if err := os.Link(ipv4HostRolePath, "/etc/alinksec/linked"); err != nil {
		t.Fatal(err)
	}
	errorRequired()
	os.Remove("/etc/alinksec/linked")
	os.Remove(ipv4HostRolePath)
	errorRequired()
	if err := os.Symlink("/etc/hostname", ipv4HostRolePath); err != nil {
		t.Fatal(err)
	}
	errorRequired()
	os.Remove(ipv4HostRolePath)
	if err := unix.Mkfifo(ipv4HostRolePath, 0644); err != nil {
		t.Fatal(err)
	}
	errorRequired()
	os.Remove(ipv4HostRolePath)
	writeRole()
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	r := ipv4HostWithin(ctx, &cs, ipv4HostRolePath, func() (ipv4HostSnapshot, error) {
		if err := os.WriteFile(ipv4HostRolePath, []byte("router\n"), 0644); err != nil {
			t.Fatal(err)
		}
		return goodIPv4Snapshot(), nil
	})
	cancel()
	if !r.Error || r.Passed {
		t.Fatal("changed role accepted", r)
	}
	// Mandatory fault injection covers bounded reads and namespace/interface/value
	// changes without mutating the real kernel or relying on timing races.
	t.Run("mandatory_reader_boundaries", TestIPv4HostBoundedProcReader)
	t.Run("mandatory_changes_and_deadline", TestIPv4HostChangesAndDeadlineAreErrors)
}
