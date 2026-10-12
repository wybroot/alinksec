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
        assertTrue(VulnMatchService.versionInRange("1.2.3", "1.2.3"));
        assertFalse(VulnMatchService.versionInRange("1.2.4", "1.2.3"));
        assertFalse(VulnMatchService.versionInRange("1.2.3", "<"));
        assertFalse(VulnMatchService.versionInRange("", "<1.0"));   // 版本缺失不误报
        assertFalse(VulnMatchService.versionInRange(null, "<1.0"));
    }

    @Test
    void importedRulesRequireTheConfiguredProductOsAndSourceAndAllBounds() {
        var rule = scoped("{\"name\":\"openssl\",\"match\":\"exact\",\"os\":\"ubuntu22.04\",\"source\":\"dpkg\",\"ranges\":[\">=1.0\",\"<2.0\"]}", "dpkg");
        assertTrue(matches(rule, "openssl", "1.5", "ubuntu22.04", "dpkg"));
        assertFalse(matches(rule, "openssl-libs", "1.5", "ubuntu22.04", "dpkg"));
        assertFalse(matches(rule, "OpenSSL", "1.5", "ubuntu22.04", "dpkg"));
        assertFalse(matches(rule, "openssl", "1.5", "rhel9", "dpkg"));
        assertFalse(matches(rule, "openssl", "1.5", "ubuntu22.04", "rpm"));
        assertFalse(matches(rule, "openssl", "0.9", "ubuntu22.04", "dpkg"));
        assertFalse(matches(rule, "openssl", "2.0", "ubuntu22.04", "dpkg"));
    }

    @Test
    void rangeBoundaryDoesNotInventAConfirmedVendorFix() {
        assertNull(VulnMatchService.rangeFixedVersion("<1.1.1n"));
        assertNull(VulnMatchService.rangeFixedVersion("<=9.8p1"));
        assertNull(VulnMatchService.rangeFixedVersion("*"));
        assertNull(VulnMatchService.rangeFixedVersion(""));
    }

    @Test void packageRulesUseSourceSpecificOrderingWithoutMalformedFallback() {
        var rpm = scoped("{\"name\":\"openssl\",\"match\":\"exact\",\"source\":\"rpm\",\"ranges\":[\"<1:3.0.7-27.el9_4.1\"]}", "rpm");
        assertTrue(matches(rpm, "openssl", "1:3.0.7-27.el9_4", "rocky 9.4", "rpm"));
        assertFalse(matches(rpm, "openssl", "2:1.0-1", "rocky 9.4", "rpm"));
        assertFalse(matches(rpm, "openssl", "malformed version", "rocky 9.4", "rpm"));
        var dpkg = scoped("{\"name\":\"fixture\",\"source\":\"dpkg\",\"vrange\":\"<1.0-1ubuntu10\"}", "dpkg");
        assertTrue(matches(dpkg, "fixture", "1.0-1ubuntu2", "ubuntu 24.04", "dpkg"));
        assertFalse(matches(dpkg, "fixture", "1:0.1-1", "ubuntu 24.04", "dpkg"));
    }

    @Test void explicitUpstreamRangesCannotBeAppliedToDistributionPackageVersions() {
        var rule = scoped("{\"name\":\"fixture\",\"source\":\"dpkg\",\"vrange\":\"<9.0\"}", "dpkg");
        ((com.fasterxml.jackson.databind.node.ObjectNode) rule).put("version_scheme", "upstream");
        assertFalse(matches(rule, "fixture", "1.0-1ubuntu1", "ubuntu 24.04", "dpkg"));
        ((com.fasterxml.jackson.databind.node.ObjectNode) rule).put("version_scheme", "dpkg");
        assertTrue(matches(rule, "fixture", "1.0-1ubuntu1", "ubuntu 24.04", "dpkg"));
        ((com.fasterxml.jackson.databind.node.ObjectNode) rule).put("version_scheme", "unknown");
        assertFalse(matches(rule, "fixture", "1.0-1ubuntu1", "ubuntu 24.04", "dpkg"));
    }

    @Test void nativeScopeCannotUseDisplayOsFamilyOrRuntimeArchitectureAsEvidence() {
        var rule = scoped("{\"name\":\"fixture\",\"source\":\"dpkg\",\"vrange\":\"<2.0\"}", "dpkg");
        assertTrue(matches(rule, "fixture", "1.0", "Ubuntu 24.04", "dpkg"));
        assertFalse(VulnMatchService.ruleMatches(rule, "fixture", "1.0", "Ubuntu 24.04", "dpkg", "debian", "24.04", "amd64", true));
        assertFalse(VulnMatchService.ruleMatches(rule, "fixture", "1.0", "Ubuntu 24.04", "dpkg", "ubuntu", "22.04", "amd64", true));
        assertFalse(VulnMatchService.ruleMatches(rule, "fixture", "1.0", "Ubuntu 24.04", "dpkg", "ubuntu", "24.04", "i386", true));
        assertFalse(VulnMatchService.ruleMatches(rule, "fixture", "1.0", "Ubuntu 24.04", "dpkg", "ubuntu", "24.04", "amd64", false));
        ((com.fasterxml.jackson.databind.node.ObjectNode) rule).put("architecture", "*");
        assertTrue(VulnMatchService.ruleMatches(rule, "fixture", "1.0", "Ubuntu 24.04", "dpkg", "ubuntu", "24.04", "i386", true));
        assertFalse(VulnMatchService.ruleMatches(rule, "fixture", "1.0", "Ubuntu 24.04", "dpkg", "ubuntu", "24.04", "", true));
        for (String field : java.util.List.of("distro_id", "distro_version", "architecture", "version_scheme", "source")) {
            var incomplete = rule.deepCopy(); ((com.fasterxml.jackson.databind.node.ObjectNode) incomplete).remove(field);
            assertFalse(matches(incomplete, "fixture", "1.0", "Ubuntu 24.04", "dpkg"));
        }
    }

    private static com.fasterxml.jackson.databind.JsonNode scoped(String json, String source) {
        var rule = (com.fasterxml.jackson.databind.node.ObjectNode) com.alinksec.common.util.JsonUtils.read(json);
        return rule.put("version_scheme", source).put("distro_id", "ubuntu").put("distro_version", "24.04").put("architecture", "amd64");
    }
    private static boolean matches(com.fasterxml.jackson.databind.JsonNode rule, String name, String version, String os, String source) {
        return VulnMatchService.ruleMatches(rule, name, version, os, source, "ubuntu", "24.04", "amd64", true);
    }
}
