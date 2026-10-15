//go:build linux

package collector

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func TestRPMInventoryRetainsEpochReleaseVendorAndInstallTime(t *testing.T) {
	input := "openssl\x1f1\x1f3.0.7\x1f27.el9_4\x1fVendor with spaces\x1f1000\x1fx86_64\n" +
		"fixture\x1f0\x1f1.0\x1f1\x1fVendor\x1f9223372036854775807\x1fnoarch\n"
	items, err := parseRPMPackages(input)
	if len(items) != 2 || items[0].Version != "1:3.0.7-27.el9_4" || items[0].Source != "rpm" ||
		err != nil || items[0].Architecture != "x86_64" || items[1].Architecture != "noarch" ||
		items[0].Vendor != "Vendor with spaces" || items[0].InstallTime != 1000000 || items[1].InstallTime != 0 {
		t.Fatalf("unexpected full RPM inventory: %+v", items)
	}
	for _, line := range []string{"fixture\x1f1.0-1\x1fVendor\x1f1000\n", "fixture\x1f(none)\x1f1.0\x1f1\x1fVendor\x1f1000\n", "fixture\x1f0\x1f1.0\x1f\x1fVendor\x1f1000\n"} {
		if items, err := parseRPMPackages(line); err == nil || len(items) != 0 {
			t.Fatal("incomplete RPM version was converted to an apparently complete asset")
		}
	}
}

func TestDPKGInventoryIncludesHeldAndMultipleArchitectures(t *testing.T) {
	items, err := parseDPKGPackages("libc6\x1f2:2.39-0ubuntu8.6\x1fii \x1famd64\n" +
		"libc6\x1f2:2.39-0ubuntu8.6\x1fhi \x1fi386\n" +
		"removed\x1f1.0\x1frc \x1fall\n")
	if err != nil || len(items) != 2 || items[0].Name != items[1].Name || items[1].Architecture != "i386" ||
		items[0].Version != "2:2.39-0ubuntu8.6" {
		t.Fatalf("held or multiarch package lost: %v %+v", err, items)
	}
	for _, line := range []string{"broken", "pkg\x1f1.0\x1fii \x1f\n", "pkg\x1f\x1fii \x1famd64\n",
		"pkg\x1f1.0\x1fiFR\x1famd64\n", "pkg\x1f1.0\x1fiiR\x1famd64\n"} {
		if _, err := parseDPKGPackages(line); err == nil {
			t.Fatal("malformed installed record treated as complete")
		}
	}
}

func TestSoftwareAttemptDistinguishesEmptyFailureAndDualDatabases(t *testing.T) {
	lookup := func(name string) (string, error) { return name, nil }
	for _, scenario := range []struct {
		name, rpm, dpkg string
		failure         bool
		count           int
	}{
		{"empty", "", "", false, 0},
		{"both", "pkg\x1f0\x1f1.0\x1f1\x1fVendor\x1f0\x1fi686\n", "pkg\x1f1.0\x1fii \x1famd64\n", false, 2},
		{"partial-command-failure", "pkg\x1f0\x1f1.0\x1f1\x1fVendor\x1f0\x1fx86_64\n", "", true, 0},
		{"malformed", "", "broken\n", false, 0},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			snap := &pb.RptAssetSnapshot{}
			collectLinuxSoftware(snap, &pb.SoftwareInventory{}, lookup, func(name string, args ...string) ([]byte, error) {
				if name == "rpm" {
					return []byte(scenario.rpm), nil
				}
				if scenario.failure {
					return nil, errors.New("fixture query failure")
				}
				return []byte(scenario.dpkg), nil
			})
			complete := !scenario.failure && scenario.name != "malformed"
			if (snap.SoftwareInventory.Status == pb.SoftwareInventory_COMPLETE) != complete || len(snap.Software) != scenario.count {
				t.Fatalf("unexpected attempt: %+v", snap)
			}
			if complete && snap.SoftwareInventory.Source != "mixed" {
				t.Fatal("source was inferred from nonempty output")
			}
		})
	}
	snap := &pb.RptAssetSnapshot{}
	collectLinuxSoftware(snap, &pb.SoftwareInventory{}, func(string) (string, error) { return "", exec.ErrNotFound }, nil)
	if snap.SoftwareInventory.Status != pb.SoftwareInventory_UNSUPPORTED {
		t.Fatal("unsupported host treated as empty inventory")
	}
}

func TestDistributionIdentityDoesNotInferReleaseOrExecuteShell(t *testing.T) {
	identity := parseDistributionIdentity("ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=ignored\n")
	if identity.DistroId != "ubuntu" || identity.DistroVersion != "24.04" || identity.IdentityError != "" {
		t.Fatal(identity)
	}
	for _, input := range []string{"ID_LIKE=debian\nPRETTY_NAME=Ubuntu 24.04\n", "ID=debian\nVERSION_CODENAME=bookworm\n"} {
		identity = parseDistributionIdentity(input)
		if identity.DistroVersion != "" || identity.IdentityError == "" {
			t.Fatal("inferred release identity", identity)
		}
	}
	for _, input := range []string{"ID=ubuntu\nID=debian", "ID=\"$(touch /tmp/never)\"", "ID=ubuntu\nVERSION_ID=\"24.04", "ID=ubuntu\nVERSION_ID='${VERSION}'"} {
		if parseDistributionIdentity(input).IdentityError != "distribution_identity_invalid" {
			t.Fatal("accepted invalid identity", input)
		}
	}
}

func TestSoftwareOutputLimitRejectsTruncation(t *testing.T) {
	var out softwareOutput
	if _, err := out.Write([]byte(strings.Repeat("x", softwareOutputLimit))); err != nil {
		t.Fatal(err)
	}
	if _, err := out.Write([]byte("x")); err == nil {
		t.Fatal("oversized output treated as complete")
	}
}

func TestSoftwareQueryStopsAtDeadlineAndRejectsNonzeroExit(t *testing.T) {
	start := time.Now()
	if out, err := runSoftwareQueryWithTimeout(50*time.Millisecond, "/bin/sh", "-c", "sleep 30"); err == nil || len(out) != 0 {
		t.Fatal("timed-out query returned an apparently complete inventory")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("software query deadline did not stop the process group")
	}
	if _, err := runSoftwareQuery("/bin/sh", "-c", "exit 1"); err == nil {
		t.Fatal("nonzero query treated as empty success")
	}
}

// Required in CI on Ubuntu and in the isolated Rocky9 image. This exercises the
// real package database and preserves native architecture spellings.
func TestNativeSoftwareInventory(t *testing.T) {
	if os.Getenv("ALINKSEC_SOFTWARE_NATIVE_REQUIRED") != "true" {
		t.Skip("native inventory check not requested")
	}
	snap := &pb.RptAssetSnapshot{}
	collectSoftware(snap)
	if snap.SoftwareInventory.Status != pb.SoftwareInventory_COMPLETE || len(snap.Software) == 0 ||
		snap.SoftwareInventory.DistroId == "" || snap.SoftwareInventory.DistroVersion == "" {
		t.Fatalf("native inventory incomplete: %+v", snap.SoftwareInventory)
	}
	for _, pkg := range snap.Software {
		if pkg.Architecture == "" || pkg.Version == "" {
			t.Fatal("native package identity missing", pkg)
		}
	}
	t.Logf("distribution=%s/%s source=%s packages=%d first=%s/%s", snap.SoftwareInventory.DistroId,
		snap.SoftwareInventory.DistroVersion, snap.SoftwareInventory.Source, len(snap.Software), snap.Software[0].Name, snap.Software[0].Architecture)
}
