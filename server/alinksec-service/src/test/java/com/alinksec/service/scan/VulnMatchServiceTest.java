package com.alinksec.service.scan;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 版本比较器与 vrange 判定单测（种子 CVE 数据覆盖的典型格式）。
 */
class VulnMatchServiceTest {

    @Test
    void compareVersions_semver_numeric() {
        assertTrue(VulnMatchService.compareVersions("6.7.9", "6.7.10") < 0);
        assertTrue(VulnMatchService.compareVersions("2.4.58", "2.4.57") > 0);
        assertEquals(0, VulnMatchService.compareVersions("8.4.0", "8.4.0"));
    }

    @Test
    void compareVersions_openssl_patch_letter() {
        // openssl 序：1.1.1 < 1.1.1a < 1.1.1k < 1.1.1n < 1.1.1z
        assertTrue(VulnMatchService.compareVersions("1.1.1", "1.1.1a") < 0);
        assertTrue(VulnMatchService.compareVersions("1.1.1k", "1.1.1n") < 0);
        assertTrue(VulnMatchService.compareVersions("1.1.1z", "1.1.1n") > 0);
    }

    @Test
    void compareVersions_suffix_after_number() {
        // sudo：1.9.5 < 1.9.5p2；9.8 < 9.8p1
        assertTrue(VulnMatchService.compareVersions("1.9.5", "1.9.5p2") < 0);
        assertTrue(VulnMatchService.compareVersions("9.8p1", "9.8") > 0);
        assertTrue(VulnMatchService.compareVersions("13.1-49.13", "13.1-49.15") < 0);
    }

    @Test
    void versionInRange_operator() {
        assertTrue(VulnMatchService.versionInRange("1.1.1k", "<1.1.1n"));
        assertFalse(VulnMatchService.versionInRange("1.1.1n", "<1.1.1n"));
        assertTrue(VulnMatchService.versionInRange("1.1.1n", "<=1.1.1n"));
        assertTrue(VulnMatchService.versionInRange("9.8p1", ">=9.8p1"));
        assertTrue(VulnMatchService.versionInRange("6.7.9", "<6.7.10"));
        assertFalse(VulnMatchService.versionInRange("6.7.10", "<6.7.10"));
        assertTrue(VulnMatchService.versionInRange("6.7.9", "<6.8"));
        assertTrue(VulnMatchService.versionInRange("anything", "*"));
        assertFalse(VulnMatchService.versionInRange("", "<1.0"));   // 版本缺失不误报
        assertFalse(VulnMatchService.versionInRange(null, "<1.0"));
    }

    @Test
    void rangeFixedVersion_extract() {
        assertEquals("1.1.1n", VulnMatchService.rangeFixedVersion("<1.1.1n"));
        assertEquals("9.8p1", VulnMatchService.rangeFixedVersion("<=9.8p1"));
        assertNull(VulnMatchService.rangeFixedVersion("*"));
        assertNull(VulnMatchService.rangeFixedVersion(""));
    }
}
