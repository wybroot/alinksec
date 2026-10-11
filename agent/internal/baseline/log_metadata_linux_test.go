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

	"golang.org/x/sys/unix"
)

func logFixture(t *testing.T, target string) (string, string, *CheckSpec) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "var/log"), 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, target)
	if target == "/var/log/audit" {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := os.WriteFile(path, []byte("DO_NOT_REPORT_LOG_CONTENT"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	group := filepath.Join(root, "group")
	if err := os.WriteFile(group, []byte("root:x:0:\nutmp:x:0:\n"), 0644); err != nil {
		t.Fatal(err)
	}
	perm, expectedGroup := logMetadataPolicy(target)
	return root, group, &CheckSpec{Type: "linux_log_metadata", Target: target, Operator: "subset", Perm: perm, Owner: "0", Group: expectedGroup, TimeoutMs: 1000}
}

func TestLogMetadataRejectsAmbiguousTargets(t *testing.T) {
	for _, kind := range []string{"missing", "symlink", "parent-link", "fifo", "directory", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			root, group, cs := logFixture(t, "/var/log/btmp")
			path := filepath.Join(root, cs.Target)
			if kind == "hardlink" {
				if err := os.Link(path, filepath.Join(root, "alias")); err != nil {
					t.Fatal(err)
				}
			} else if kind == "parent-link" {
				parent := filepath.Join(root, "var/log")
				if err := os.Rename(parent, parent+"-real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(parent+"-real", parent); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "symlink":
					if err := os.Symlink(group, path); err != nil {
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
				}
			}
			start := time.Now()
			result := logMetadataWithin(cs, root, group)
			if !result.Error || result.Passed || time.Since(start) > time.Second {
				t.Fatalf("ambiguous target blocked or passed: %+v", result)
			}
		})
	}
	root, group, cs := logFixture(t, "/var/log/audit")
	path := filepath.Join(root, cs.Target)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0700); err != nil {
		t.Fatal(err)
	}
	if result := logMetadataWithin(cs, root, group); !result.Error {
		t.Fatal("audit file mistaken for directory")
	}
}

func logACL() []byte {
	acl := make([]byte, 4+5*8)
	binary.LittleEndian.PutUint32(acl, 2)
	for i, e := range []struct {
		tag, perm uint16
		id        uint32
	}{{1, 7, ^uint32(0)}, {2, 4, 12345}, {4, 0, ^uint32(0)}, {16, 4, ^uint32(0)}, {32, 0, ^uint32(0)}} {
		at := 4 + i*8
		binary.LittleEndian.PutUint16(acl[at:], e.tag)
		binary.LittleEndian.PutUint16(acl[at+2:], e.perm)
		binary.LittleEndian.PutUint32(acl[at+4:], e.id)
	}
	return acl
}

func TestNativeLogMetadata(t *testing.T) {
	required := os.Getenv("ALINKSEC_LOG_METADATA_NATIVE_REQUIRED") == "true"
	if os.Geteuid() != 0 {
		if required {
			t.Fatal("root required")
		}
		t.Skip("root required for numerical ownership fixtures")
	}
	raw, err := os.ReadFile("../../../deploy/baseline/packages/log-metadata/linux-baseline.json")
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
	if len(doc.Items) != 3 {
		t.Fatal("three fixed reference paths required")
	}
	for _, item := range doc.Items {
		t.Run(item.Code, func(t *testing.T) {
			cs, err := ParseCheck(string(item.Check))
			if err != nil {
				t.Fatal(err)
			}
			root, group, _ := logFixture(t, cs.Target)
			path := filepath.Join(root, cs.Target)
			if cs.Target != "/var/log/audit" {
				if err := os.Truncate(path, 16*1024*1024); err != nil {
					t.Fatal(err)
				}
			}
			for _, mode := range []os.FileMode{0600, 0000} {
				if err := os.Chmod(path, mode); err != nil {
					t.Fatal(err)
				}
				result := logMetadataWithin(cs, root, group)
				if result.Error || !result.Passed || strings.Contains(result.Actual+result.Message, "DO_NOT_REPORT") {
					t.Fatalf("stricter metadata rejected or content leaked: %+v", result)
				}
				t.Logf("native log metadata %s mode=%04o passed=%v error=%v actual=%s", item.Code, mode, result.Passed, result.Error, result.Actual)
			}
			if err := os.Chmod(path, 0777); err != nil {
				t.Fatal(err)
			}
			if result := logMetadataWithin(cs, root, group); result.Error || result.Passed {
				t.Fatalf("excess permissions accepted: %+v", result)
			}
			if err := os.Chmod(path, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(path, 65534, 65534); err != nil {
				if required {
					t.Fatal(err)
				}
				t.Skip("local UID mapping cannot create ownership fixture")
			}
			if result := logMetadataWithin(cs, root, group); result.Error || result.Passed {
				t.Fatalf("wrong IDs accepted: %+v", result)
			}
			if err := os.Chown(path, 0, 0); err != nil {
				t.Fatal(err)
			}
			if cs.Group == "utmp" {
				if err := os.WriteFile(group, []byte("root:x:0:\n"), 0644); err != nil {
					t.Fatal(err)
				}
				if result := logMetadataWithin(cs, root, group); !result.Error {
					t.Fatal("missing group used fallback")
				}
			}
		})
	}
	for _, attribute := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		t.Run(attribute, func(t *testing.T) {
			root, group, cs := logFixture(t, "/var/log/audit")
			if err := unix.Setxattr(filepath.Join(root, cs.Target), attribute, logACL(), 0); err != nil {
				if required {
					t.Fatal(err)
				}
				t.Skip("local filesystem cannot create ACL fixture")
			}
			if result := logMetadataWithin(cs, root, group); !result.Error || result.Passed || !strings.Contains(result.Message, "ACL") {
				t.Fatalf("ACL ignored: %+v", result)
			}
		})
	}
	for _, item := range doc.Items {
		cs, _ := ParseCheck(string(item.Check))
		result := checkLogMetadata(cs)
		t.Logf("host log metadata %s passed=%v error=%v actual=%s message=%s", item.Code, result.Passed, result.Error, result.Actual, result.Message)
	}
}
