//go:build linux

package fixer

import (
	"errors"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPackageHeaderKeepsFullBinaryIdentityAndRejectsMalformedOrSourcePackages(t *testing.T) {
	for _, tc := range []struct{ repo, output, version string }{
		{"deb", "fixture\x1f1:1.0-1ubuntu2\x1famd64\n", "1:1.0-1ubuntu2"},
		{"rpm", "fixture\x1f2\x1f1.0\x1f3.el9\x1fx86_64\n", "2:1.0-3.el9"},
	} {
		metadata, err := parsePackageMetadata(tc.repo, tc.output)
		if err != nil || metadata.Name != "fixture" || metadata.Version != tc.version {
			t.Fatal("binary metadata lost", metadata, err)
		}
	}
	for _, output := range []string{"fixture\x1f0\x1f1.0\x1f1\x1fsrc\n", "fixture\x1f0\x1f1.0\x1f1\x1fnosrc\n", "fixture\x1f0\x1f1.0\x1f1\x1fx86_64\nsecond\n", "fixture\x1f(none)\x1f1.0\x1f1\x1fx86_64\n"} {
		if _, err := parsePackageMetadata("rpm", output); err == nil {
			t.Fatal("malformed/source package accepted")
		}
	}
}

func TestInstallationSnapshotRejectsDuplicateNamesAcrossArchitecturesAndSources(t *testing.T) {
	base := &pb.SoftwareInfo{Name: "fixture", Version: "1.0-1", Source: "dpkg", Architecture: "amd64"}
	snapshot := &pb.RptAssetSnapshot{Software: []*pb.SoftwareInfo{base}, SoftwareInventory: &pb.SoftwareInventory{Status: pb.SoftwareInventory_COMPLETE, DistroId: "ubuntu", DistroVersion: "24.04", Source: "mixed", PackageRepairContract: 1}}
	if _, err := installationFromSnapshot("fixture", snapshot); err != nil {
		t.Fatal(err)
	}
	for _, other := range []*pb.SoftwareInfo{{Name: "fixture", Version: "1.0-1", Source: "dpkg", Architecture: "i386"}, {Name: "fixture", Version: "1.0-1", Source: "rpm", Architecture: "x86_64"}} {
		snapshot.Software = append([]*pb.SoftwareInfo{base}, other)
		if _, err := installationFromSnapshot("fixture", snapshot); err == nil {
			t.Fatal("ambiguous installed identity accepted")
		}
	}
	snapshot.Software = []*pb.SoftwareInfo{base}
	snapshot.SoftwareInventory.Status = pb.SoftwareInventory_FAILED
	if _, err := installationFromSnapshot("fixture", snapshot); err == nil {
		t.Fatal("failed inventory accepted")
	}
}

func TestNativeDebianPackageMetadataIsReadWithoutRunningMaintainerScripts(t *testing.T) {
	if _, err := exec.LookPath("dpkg-deb"); err != nil {
		if os.Getenv("ALINKSEC_PACKAGE_REPAIR_NATIVE_REQUIRED") == "true" {
			t.Fatal(err)
		}
		t.Skip("native Debian package builder unavailable")
	}
	root := t.TempDir()
	control := filepath.Join(root, "input", "DEBIAN")
	if err := os.MkdirAll(control, 0755); err != nil {
		t.Fatal(err)
	}
	content := "Package: fixture\nVersion: 1:2.0-1ubuntu1\nArchitecture: all\nMaintainer: Fixture <fixture@example.invalid>\nDescription: bounded parser fixture\n"
	if err := os.WriteFile(filepath.Join(control, "control"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "executed")
	if err := os.WriteFile(filepath.Join(control, "preinst"), []byte("#!/bin/sh\ntouch '"+marker+"'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "fixture.deb")
	if output, err := exec.Command("dpkg-deb", "--build", "--root-owner-group", filepath.Join(root, "input"), file).CombinedOutput(); err != nil {
		t.Fatal(string(output), err)
	}
	metadata, err := inspectPackage(&PkgPayload{RepoType: "deb"}, file)
	if err != nil || metadata.Name != "fixture" || metadata.Version != "1:2.0-1ubuntu1" || metadata.Architecture != "all" {
		t.Fatal(metadata, err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("package inspection executed maintainer script")
	}
}

func TestNativePackageCommandStopsTimeoutAndOutputAndEnforcesParserLimits(t *testing.T) {
	for _, tc := range []struct {
		script  string
		timeout time.Duration
	}{
		{"sleep 30", 50 * time.Millisecond}, {"while :; do printf '0123456789abcdef'; done", time.Second},
	} {
		if _, err := packageCommand(false, tc.timeout, "sh", "-c", tc.script); err == nil {
			t.Fatal("unbounded command accepted")
		}
	}
	output, err := packageCommand(true, time.Second, "sh", "-c", "ulimit -v; ulimit -t")
	if err != nil || strings.TrimSpace(string(output)) != "262144\n10" {
		t.Fatal("metadata process resource limits missing", string(output), err)
	}
}

func TestNativeRPMPackageMetadataIsReadWithoutRunningPackageScripts(t *testing.T) {
	if _, err := exec.LookPath("rpmbuild"); err != nil {
		if os.Getenv("ALINKSEC_RPM_REPAIR_NATIVE_REQUIRED") == "true" {
			t.Fatal(err)
		}
		t.Skip("isolated RPM builder unavailable")
	}
	root := t.TempDir()
	marker := filepath.Join(root, "executed")
	spec := "Name: fixture\nEpoch: 2\nVersion: 1.0\nRelease: 3.el9\nSummary: disposable fixture\nLicense: MIT\nBuildArch: noarch\n%description\nbounded header fixture\n%pre\ntouch '" + marker + "'\n%files\n"
	file := filepath.Join(root, "fixture.spec")
	if err := os.WriteFile(file, []byte(spec), 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := packageCommand(false, 20*time.Second, "rpmbuild", "-bb", "--define", "_topdir "+root, file); err != nil {
		t.Fatal(string(output), err)
	}
	packages, err := filepath.Glob(filepath.Join(root, "RPMS", "noarch", "*.rpm"))
	if err != nil || len(packages) != 1 {
		t.Fatal("missing unique binary RPM", packages, err)
	}
	metadata, err := inspectPackage(&PkgPayload{RepoType: "rpm"}, packages[0])
	if err != nil || metadata.Name != "fixture" || metadata.Version != "2:1.0-3.el9" || metadata.Architecture != "noarch" || metadata.Source != "rpm" {
		t.Fatal(metadata, err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("header inspection executed package script")
	}
}

func TestInstalledRPMQueryRejectsAmbiguousMultiArchitectureOutput(t *testing.T) {
	if got := rpmInstalledVersion("1\x1f3.0.7\x1f27.el9_4\n"); got != "1:3.0.7-27.el9_4" {
		t.Fatalf("full installed version=%q", got)
	}
	for _, out := range []string{"", "(none)\x1f1.0\x1f1\n", "0\x1f1.0\x1f1\n0\x1f1.0\x1f1\n", "0\x1f1.0\x1f1\r\n"} {
		if rpmInstalledVersion(out) != "" {
			t.Fatal("unresolved package identity was accepted for verification")
		}
	}
}
