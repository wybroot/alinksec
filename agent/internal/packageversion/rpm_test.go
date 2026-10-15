package packageversion

import "testing"

func TestRPMRetainsEpochAndFullRelease(t *testing.T) {
	for _, tc := range []struct{ epoch, version, release, want string }{
		{"0", "3.0.7", "27.el9_4", "0:3.0.7-27.el9_4"},
		{"1", "3.0.7", "27.el9_4", "1:3.0.7-27.el9_4"},
		{"0002", "1.0~rc1", "1", "2:1.0~rc1-1"},
		{"4294967295", "1.0^git1", "1", "4294967295:1.0^git1-1"},
	} {
		got, err := RPM(tc.epoch, tc.version, tc.release)
		if err != nil || got != tc.want {
			t.Fatalf("RPM version=%q error=%v want=%q", got, err, tc.want)
		}
	}
	for _, tc := range [][3]string{{"", "1", "1"}, {"(none)", "1", "1"}, {"-1", "1", "1"}, {"4294967296", "1", "1"}, {"0", "", "1"}, {"0", "1", ""}, {"0", "1\n", "1"}, {"0", "1", "1:bad"}} {
		if _, err := RPM(tc[0], tc[1], tc[2]); err == nil {
			t.Fatal("unknown RPM fields were accepted")
		}
	}
}

func TestRPMIdentityNormalizesOnlyTheEpoch(t *testing.T) {
	for _, value := range []string{"3.0.7-27.el9", "0:3.0.7-27.el9", "0000:3.0.7-27.el9"} {
		got, err := RPMIdentity(value)
		if err != nil || got != "0:3.0.7-27.el9" {
			t.Fatalf("identity=%q error=%v", got, err)
		}
	}
	for _, value := range []string{"3.0.7", "1:", ":3.0.7-1", "3.0.7-", "bad version-1", "1:3.0.7-1\n"} {
		if _, err := RPMIdentity(value); err == nil {
			t.Fatal("ambiguous RPM identity was accepted")
		}
	}
}
