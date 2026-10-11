//go:build linux

package baseline

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"golang.org/x/sys/unix"
)

func TestNativeProgramFiles(t *testing.T) {
	if os.Getenv("ALINKSEC_PROGRAM_FILES_NATIVE_REQUIRED") != "true" {
		t.Skip("explicit disposable Ubuntu24 only")
	}
	marker, err := os.ReadFile("/usr/local/lib/alinksec-pam-fixture")
	if os.Geteuid() != 0 || os.Getenv("ALINKSEC_PROGRAM_FILES_ISOLATED_REQUIRED") != "true" || err != nil || string(marker) != "isolated-pam-fixture-v1\n" {
		t.Fatal("root, both switches and disposable image marker required")
	}
	p := programFilesFixture(t)
	check := func(option, reference string, pass, errorWant bool) {
		t.Helper()
		s := programFilesSpec(option)
		s.TimeoutMs = 5000
		if reference != "" {
			s.Expected = programReferenceExpected(reference)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		r := programFilesWithin(ctx, &s, p, queryProgramLibcVersions)
		t.Logf("native program files option=%s passed=%t error=%t actual=%s message=%s", option, r.Passed, r.Error, r.Actual, r.Message)
		if r.Passed != pass || r.Error != errorWant {
			t.Fatal(r)
		}
	}
	check("linker_metadata", "", true, false)
	// Native ldconfig only reads an isolated filesystem replica. Both -N and -X
	// suppress cache/link writes; -r excludes host paths and library directories.
	cmd := exec.Command("/usr/sbin/ldconfig", "-r", p.root, "-N", "-X", "-v")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	if raw, err := cmd.CombinedOutput(); err != nil {
		t.Fatal("native private linker configuration rejected", err, string(raw))
	}
	check("privileged_reference", privilegedReferenceHeader, true, false)
	var rows []string
	for _, fixture := range []struct {
		path, body, mode string
		gid              int
	}{{"/usr/bin/fixture-suid", "never execute suid\n", "4755", 0}, {"/usr/sbin/fixture-sgid", "never execute sgid\n", "2755", 123}} {
		path := p.path(fixture.path)
		if err := os.WriteFile(path, []byte(fixture.body), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, 0, fixture.gid); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0755)
		if fixture.mode == "4755" {
			mode |= os.ModeSetuid
		} else {
			mode |= os.ModeSetgid
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		probe := exec.Command("/usr/bin/stat", "-c", "%a %u %g", path)
		raw, err := probe.Output()
		if err != nil || strings.TrimSpace(string(raw)) != fmt.Sprintf("%s 0 %d", fixture.mode, fixture.gid) {
			t.Fatal("native numerical metadata differs", err, string(raw))
		}
		digest := fmt.Sprintf("%x", sha256.Sum256([]byte(fixture.body)))
		raw, err = exec.Command("/usr/bin/sha256sum", path).Output()
		if err != nil || !strings.HasPrefix(string(raw), digest+" ") {
			t.Fatal("independent native content digest differs", err, string(raw))
		}
		rows = append(rows, fmt.Sprintf("%s\t%s\t%s\t0\t%d\t%s\n", p.arch, fixture.path, fixture.mode, fixture.gid, digest))
	}
	check("privileged_reference", privilegedReferenceHeader, false, false)
	sort.Strings(rows)
	reference := privilegedReferenceHeader + strings.Join(rows, "")
	if err := os.WriteFile(p.path(privilegedReferencePath), []byte(reference), 0644); err != nil {
		t.Fatal(err)
	}
	check("privileged_reference", reference, true, false)
	if err := os.Symlink("/outside/not-followed", p.path("/usr/bin/excluded-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p.path("/usr/bin/excluded-directory"), 0755); err != nil {
		t.Fatal(err)
	}
	check("privileged_reference", reference, true, false)
	file := p.path("/usr/bin/fixture-suid")
	if err := os.WriteFile(file, []byte("changed content\n"), 0755); err != nil {
		t.Fatal(err)
	}
	os.Chmod(file, os.ModeSetuid|0755)
	check("privileged_reference", reference, false, false)
	if err := os.Chmod(file, 0755); err != nil {
		t.Fatal(err)
	}
	check("privileged_reference", reference, false, false)
	os.Chmod(file, os.ModeSetuid|0755)
	for _, target := range []string{"/etc/ld.so.conf", "/etc/alinksec/privileged-files.reference"} {
		path := p.path(target)
		option, ref := "linker_metadata", ""
		if target == privilegedReferencePath {
			option = "privileged_reference"
			ref = reference
		}
		for _, mutate := range []func() error{func() error { return os.Chown(path, 65534, 0) }, func() error { return os.Chown(path, 0, 65534) }, func() error { return unix.Setxattr(path, "system.posix_acl_access", logACL(), 0) }} {
			if err := mutate(); err != nil {
				t.Fatal("mandatory trust boundary unavailable", err)
			}
			check(option, ref, false, true)
			os.Chown(path, 0, 0)
			unix.Removexattr(path, "system.posix_acl_access")
			os.Chmod(path, 0644)
		}
	}
	if err := unix.Setxattr(p.path("/usr/bin"), "system.posix_acl_default", logACL(), 0); err != nil {
		t.Fatal(err)
	}
	check("privileged_reference", reference, false, true)
	unix.Removexattr(p.path("/usr/bin"), "system.posix_acl_default")
	if err := unix.Setxattr(file, "system.posix_acl_access", logACL(), 0); err != nil {
		t.Fatal(err)
	}
	check("privileged_reference", reference, false, true)
	unix.Removexattr(file, "system.posix_acl_access")
	t.Run("mandatory_contract_and_exact_comparison", TestPrivilegedReferenceContractAndExactComparison)
	t.Run("mandatory_trusted_inputs_and_limits", TestProgramFilesTrustedInputAndLimits)
	t.Run("mandatory_privileged_scope_and_content", TestProgramFilesPrivilegedScopeAndContent)
	t.Run("mandatory_reference_pin_and_deadline", TestProgramFilesReferencePinAndCommonDeadline)
	t.Run("mandatory_changes", TestProgramFilesChangesAreErrors)
	for _, option := range []string{"linker_metadata", "privileged_reference"} {
		s := programFilesSpec(option)
		s.TimeoutMs = 5000
		r := checkOne(&pb.BaselineCheckSpec{ItemId: "program-product-" + option, Check: programFilesJSON(s)})
		t.Logf("native program product read-only observation: item=%s passed=%t error=%t actual=%s message=%s", r.ItemID, r.Passed, r.Error, r.Actual, r.Message)
		if r.ItemID != "program-product-"+option {
			t.Fatal(r)
		}
	}
	t.Log("Native program files: mandatory_boundaries_executed=true privileged_execution_calls=0 production_reference_writes=0")
}
