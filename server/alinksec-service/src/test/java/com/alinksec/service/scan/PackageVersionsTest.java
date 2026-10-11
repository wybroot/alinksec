package com.alinksec.service.scan;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PackageVersionsTest {
    private void order(String source, String a, String b, int sign) {
        assertEquals(sign, Integer.signum(PackageVersions.compare(source, a, b)), a + " / " + b);
        assertEquals(-sign, Integer.signum(PackageVersions.compare(source, b, a)), b + " / " + a);
    }

    @Test void rpmPreservesEpochReleaseNumericSegmentsTildeAndCaret() {
        order("rpm", "2:1.0-1", "1:99.0-999", 1);
        order("rpm", "0:1.0-1", "1.0-1", 0);
        order("rpm", "1.0-2", "1.0-10", -1);
        order("rpm", "1.9.5p2-1", "1.9.5p10-1", -1);
        order("rpm", "1.0~rc1-1", "1.0-1", -1);
        order("rpm", "1.0-1", "1.0^git1-1", -1);
        order("rpm", "1.0^git1-1", "1.0.1-1", -1);
        order("rpm", "1.a-1", "1.0-1", -1);
        order("rpm", "1.0", "1.0-0", -1);
        order("rpm", "1.00001-001", "1.1-1", 0);
        order("rpm", "1.99999999999999999999999999999999999-1", "1.100000000000000000000000000000000000-1", -1);
    }

    @Test void dpkgPreservesEpochRevisionTildeLettersAndMissingRevisionZero() {
        order("dpkg", "2:1.0-1", "1:99.0-999", 1);
        order("dpkg", "1.0", "0:1.0-0", 0);
        order("dpkg", "1.0-1ubuntu2", "1.0-1ubuntu10", -1);
        order("dpkg", "1.0~~rc1", "1.0~rc1", -1);
        order("dpkg", "1.0~rc1", "1.0", -1);
        order("dpkg", "1.0a", "1.0+git1", -1);
        order("dpkg", "1.a-1", "1.0-1", 1);
        order("dpkg", "1.00001-001", "1.1-1", 0);
        order("dpkg", "1.0-0~bpo12+1", "1.0-0", -1);
        order("dpkg", "1.9.5p2-1", "1.9.5p10-1", -1);
        order("dpkg", "1.99999999999999999999999999999999999", "1.100000000000000000000000000000000000", -1);
    }

    @Test void unknownOrMalformedVersionsCannotUseAnotherComparator() {
        for (String source : new String[]{"rpm", "dpkg"}) {
            for (String value : new String[]{"", " ", "1.0 ", "1.0\n", "1.0\u0000", "1.é", ":1.0", "a:1.0", "-1:1.0", "1:", "1.0-", "1".repeat(256)}) {
                assertThrows(IllegalArgumentException.class, () -> PackageVersions.compare(source, value, "1.0"), source + "/" + value);
            }
        }
        for (String value : new String[]{"1.0^git1", "1_0", "alpha", "2147483648:1.0", "1.0-1:extra"}) {
            assertThrows(IllegalArgumentException.class, () -> PackageVersions.compare("dpkg", value, "1.0"));
        }
        assertThrows(IllegalArgumentException.class, () -> PackageVersions.compare("registry", "1.0", "2.0"));
        assertThrows(IllegalArgumentException.class, () -> PackageVersions.compare("rpm", null, "1.0"));
    }

    @Test void nativeBoundsUseTheirFullOrderingAndRejectMalformedWildcardAssets() {
        assertTrue(PackageVersions.inRange("rpm", "1:1.0-1", ">0:99.0-99"));
        assertFalse(PackageVersions.inRange("rpm", "2:1.0-1", "<1:99.0-99"));
        assertTrue(PackageVersions.inRange("dpkg", "1.0~rc1-1", "<1.0-1"));
        assertFalse(PackageVersions.inRange("dpkg", "1.0-1ubuntu10", "<1.0-1ubuntu2"));
        assertThrows(IllegalArgumentException.class, () -> PackageVersions.inRange("dpkg", "bad version", "*"));
    }
}
