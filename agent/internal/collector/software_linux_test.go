//go:build linux

package collector

import "testing"

func TestRPMInventoryRetainsEpochReleaseVendorAndInstallTime(t *testing.T) {
	input := "openssl\x1f1\x1f3.0.7\x1f27.el9_4\x1fVendor with spaces\x1f1000\n" +
		"fixture\x1f0\x1f1.0\x1f1\x1fVendor\x1f9223372036854775807\n"
	items := parseRPMPackages(input)
	if len(items) != 2 || items[0].Version != "1:3.0.7-27.el9_4" || items[0].Source != "rpm" ||
		items[0].Vendor != "Vendor with spaces" || items[0].InstallTime != 1000000 || items[1].InstallTime != 0 {
		t.Fatalf("unexpected full RPM inventory: %+v", items)
	}
	for _, line := range []string{"fixture\x1f1.0-1\x1fVendor\x1f1000\n", "fixture\x1f(none)\x1f1.0\x1f1\x1fVendor\x1f1000\n", "fixture\x1f0\x1f1.0\x1f\x1fVendor\x1f1000\n"} {
		if len(parseRPMPackages(line)) != 0 {
			t.Fatal("incomplete RPM version was converted to an apparently complete asset")
		}
	}
}
