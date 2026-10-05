//go:build linux

package baseline

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"golang.org/x/sys/unix"
)

const identitySecret = "DO_NOT_REPORT_PASSWORD_HASH"

func identityFixture(t *testing.T) identityPaths {
	t.Helper()
	root := t.TempDir()
	paths := identityPaths{filepath.Join(root, "passwd"), filepath.Join(root, "shadow"), filepath.Join(root, "group"), filepath.Join(root, "gshadow")}
	writeIdentity(t, paths.passwd, "root:x:0:0:root:/root:/bin/bash\nservice:x:999:999::/:/usr/sbin/nologin\nuser:x:1000:1000::/home/user:/bin/bash\n", 0644)
	writeIdentity(t, paths.shadow, "root:!"+identitySecret+":1:0:99999:7:::\nservice:*:1:0:99999:7:::\nuser:"+identitySecret+":1:0:99999:7:::\n", 0640)
	writeIdentity(t, paths.group, "root:x:0:\nshadow:x:0:\n", 0644)
	writeIdentity(t, paths.gshadow, "root:!::\nshadow:!::\n", 0640)
	return paths
}

func writeIdentity(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func identityAccountSpec(option string) *CheckSpec {
	min, max := uint32(1), uint32(999)
	s := &CheckSpec{Type: "local_accounts", Target: "/etc/passwd", Option: option, Operator: "eq", Expected: "0", TimeoutMs: 1000}
	if option == "empty_password" {
		s.Target = "/etc/shadow"
	}
	if option == "uid0_accounts" {
		s.Expected = "root"
	}
	if option == "system_shells" {
		s.UIDMin, s.UIDMax = &min, &max
	}
	return s
}

func requireIdentityRedacted(t *testing.T, result ItemResult) {
	t.Helper()
	if strings.Contains(result.Actual+result.Message, identitySecret) {
		t.Fatal("password material escaped into evidence")
	}
}

func TestLocalIdentityAccountPoliciesUseCompleteFilesAndPreserveScope(t *testing.T) {
	for _, option := range []string{"empty_password", "uid0_accounts", "system_shells"} {
		t.Run(option, func(t *testing.T) {
			paths := identityFixture(t)
			spec := identityAccountSpec(option)
			result := localIdentityWithin(spec, paths)
			requireIdentityRedacted(t, result)
			if result.Error || !result.Passed {
				t.Fatalf("complete valid fixture: %+v", result)
			}
			if option == "empty_password" {
				writeIdentity(t, paths.shadow, "root::1:0:99999:7:::\nservice:*:1:0:99999:7:::\nuser:!"+identitySecret+":1:0:99999:7:::\n", 0640)
			}
			if option == "uid0_accounts" {
				writeIdentity(t, paths.passwd, "root:x:0:0::/:/bin/bash\nalias:x:0:0::/:/bin/bash\n", 0644)
			}
			if option == "system_shells" {
				writeIdentity(t, paths.passwd, "root:x:0:0::/:/bin/bash\nservice:x:999:999::/:\nuser:x:1000:1000::/:/bin/bash\n", 0644)
			}
			result = localIdentityWithin(spec, paths)
			requireIdentityRedacted(t, result)
			if result.Error || result.Passed {
				t.Fatalf("reference mismatch must be fail: %+v", result)
			}
			if option == "system_shells" && (!strings.Contains(result.Actual, "uid_range=1..999 checked=1") || strings.Contains(result.Actual, "user(uid=1000)")) {
				t.Fatalf("scope changed: %+v", result)
			}
		})
	}
}

func TestLocalIdentityRejectsIncompleteMalformedAndChangedFilesWithoutSecrets(t *testing.T) {
	for _, content := range []string{"", "root:" + identitySecret + ":not-a-uid:0::/:/bin/bash\n", "root:x:0:0::/:/bin/bash\nroot:" + identitySecret + ":0:0::/:/bin/bash\n", "root:" + identitySecret + ":4294967295:0::/:/bin/bash\n", "root:" + identitySecret + ":0:0::/:/bin/bash\x00\n", strings.Repeat("x", 17000) + identitySecret + "\n"} {
		paths := identityFixture(t)
		writeIdentity(t, paths.passwd, content, 0644)
		result := localIdentityWithin(identityAccountSpec("empty_password"), paths)
		requireIdentityRedacted(t, result)
		if !result.Error || result.Passed {
			t.Fatalf("malformed file accepted: %+v", result)
		}
	}
	for _, content := range []string{"root:!:::::::\n", "root:!:::::::\nservice:*:::::::\nuser:*:::::::\nroot:" + identitySecret + ":::::::\n", "root:!:::::::\nservice:*:::::::\nuser:*:::::::\norphan:" + identitySecret + ":::::::\n", "root:" + identitySecret + ":invalid\n"} {
		paths := identityFixture(t)
		writeIdentity(t, paths.shadow, content, 0640)
		result := localIdentityWithin(identityAccountSpec("empty_password"), paths)
		requireIdentityRedacted(t, result)
		if !result.Error || result.Passed {
			t.Fatalf("incomplete shadow accepted: %+v", result)
		}
	}
	paths := identityFixture(t)
	err := scanIdentity(paths.passwd, 7, time.Now().Add(time.Second), func(p []string) error { return os.Chmod(paths.passwd, 0600) })
	if err == nil || !strings.Contains(err.Error(), "变化") {
		t.Fatalf("changed file accepted: %v", err)
	}
	if err := scanIdentity(paths.passwd, 7, time.Now().Add(-time.Second), func([]string) error { return nil }); err == nil {
		t.Fatal("expired read accepted")
	}
	if err := os.Truncate(paths.passwd, maxFileBytes+1); err != nil {
		t.Fatal(err)
	}
	if result := localIdentityWithin(identityAccountSpec("uid0_accounts"), paths); !result.Error {
		t.Fatal("oversized file accepted")
	}
}

func TestLocalIdentityRejectsMissingLinksDirectoriesAndFifosWithoutBlocking(t *testing.T) {
	for _, kind := range []string{"missing", "symlink", "directory", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			paths := identityFixture(t)
			path := filepath.Join(t.TempDir(), "file")
			switch kind {
			case "symlink":
				if err := os.Symlink(paths.passwd, path); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			}
			paths.passwd = path
			start := time.Now()
			result := localIdentityWithin(identityAccountSpec("uid0_accounts"), paths)
			if !result.Error || result.Passed || time.Since(start) > time.Second {
				t.Fatalf("invalid target blocked or passed: %+v", result)
			}
		})
	}
}

func nativeIdentityMetadataFixtures(t *testing.T) {
	paths := identityFixture(t)
	spec := &CheckSpec{Type: "local_identity_file", Target: "/etc/shadow", Perm: "0640", Owner: "0", Group: "shadow", Operator: "subset", TimeoutMs: 1000}
	for _, mode := range []os.FileMode{0640, 0600, 0400, 0000} {
		if err := os.Chmod(paths.shadow, mode); err != nil {
			t.Fatal(err)
		}
		if result := localIdentityWithin(spec, paths); result.Error || !result.Passed {
			t.Fatalf("stricter mode %o rejected: %+v", mode, result)
		}
	}
	for _, mode := range []os.FileMode{0644, 0660, os.ModeSetuid | 0640} {
		if err := os.Chmod(paths.shadow, mode); err != nil {
			t.Fatal(err)
		}
		if result := localIdentityWithin(spec, paths); result.Error || result.Passed {
			t.Fatalf("excessive mode %o accepted: %+v", mode, result)
		}
	}
	if err := os.Chmod(paths.shadow, 0640); err != nil {
		t.Fatal(err)
	}
	t.Run("wrong numeric IDs", func(t *testing.T) {
		if err := os.Chown(paths.shadow, 65534, 65534); err != nil {
			if os.Getenv("ALINKSEC_IDENTITY_NATIVE_REQUIRED") == "true" {
				t.Fatal(err)
			}
			t.Skip("local UID mapping cannot create this native ownership fixture")
		}
		defer os.Chown(paths.shadow, 0, 0)
		if result := localIdentityWithin(spec, paths); result.Error || result.Passed {
			t.Fatalf("wrong IDs accepted: %+v", result)
		}
	})
	writeIdentity(t, paths.group, "root:x:0:\n", 0644)
	if result := localIdentityWithin(spec, paths); !result.Error {
		t.Fatal("missing shadow group used fallback")
	}
	writeIdentity(t, paths.group, "root:x:0:\nshadow:x:0:\n", 0644)
	acl := make([]byte, 4+5*8)
	binary.LittleEndian.PutUint32(acl, 2)
	for i, entry := range []struct {
		tag, perm uint16
		id        uint32
	}{{1, 6, ^uint32(0)}, {2, 4, 12345}, {4, 4, ^uint32(0)}, {16, 4, ^uint32(0)}, {32, 0, ^uint32(0)}} {
		at := 4 + i*8
		binary.LittleEndian.PutUint16(acl[at:], entry.tag)
		binary.LittleEndian.PutUint16(acl[at+2:], entry.perm)
		binary.LittleEndian.PutUint32(acl[at+4:], entry.id)
	}
	t.Run("native extended ACL", func(t *testing.T) {
		if err := unix.Setxattr(paths.shadow, "system.posix_acl_access", acl, 0); err != nil {
			if os.Getenv("ALINKSEC_IDENTITY_NATIVE_REQUIRED") == "true" {
				t.Fatal(err)
			}
			t.Skip("local filesystem cannot create this native ACL fixture")
		}
		if result := localIdentityWithin(spec, paths); !result.Error || result.Passed || !strings.Contains(result.Message, "ACL") {
			t.Fatalf("ACL was ignored: %+v", result)
		}
	})
}

func TestNativeLocalIdentity(t *testing.T) {
	if os.Geteuid() != 0 {
		if os.Getenv("ALINKSEC_IDENTITY_NATIVE_REQUIRED") == "true" {
			t.Fatal("root required")
		}
		t.Skip("root required for protected-file observations")
	}
	raw, err := os.ReadFile("../../../deploy/baseline/packages/identity/linux-baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Items []struct {
			Code  string
			Check json.RawMessage
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Items) != 7 {
		t.Fatal("identity candidate must contain seven checks")
	}
	paths := identityFixture(t)
	for _, item := range doc.Items {
		spec, err := ParseCheck(string(item.Check))
		if err != nil {
			t.Fatal(err)
		}
		fixture := localIdentityWithin(spec, paths)
		requireIdentityRedacted(t, fixture)
		if fixture.Error || !fixture.Passed {
			t.Fatalf("shipped candidate fixture %s: %+v", item.Code, fixture)
		}
		host := checkOne(&pb.BaselineCheckSpec{ItemId: item.Code, Check: string(item.Check)})
		if host.Error {
			t.Fatalf("native host query %s: %+v", item.Code, host)
		}
		t.Logf("native identity host observation (not a compliance claim): %s %s passed=%t", item.Code, host.Actual, host.Passed)
	}
	t.Run("metadata upper bounds, numeric ownership and ACL", nativeIdentityMetadataFixtures)
}
