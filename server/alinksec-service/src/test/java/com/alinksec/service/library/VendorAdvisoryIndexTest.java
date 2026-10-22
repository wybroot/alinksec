package com.alinksec.service.library;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class VendorAdvisoryIndexTest {
    LibraryProperties.Source source(String type) {
        var source=new LibraryProperties.Source();source.setId("native-test");source.setType(type);return source;
    }
    @Test void configurationDefaultsExplicitSourceScopeAndIdentityFingerprintAreStable() {
        for(String type:VendorAdvisoryAdapter.TYPES) {
            var source=source(type);if(type.equals("debian-tracker"))source.setVendorPackages(List.of("openssl","curl"));
            VendorAdvisoryIndex.validate(source);String fingerprint=VendorAdvisoryIndex.fingerprint(source);
            source.setEnabled(!source.isEnabled());source.setIntervalMs(7_200_000);assertEquals(fingerprint,VendorAdvisoryIndex.fingerprint(source));
            source.setInitialDays(14);assertNotEquals(fingerprint,VendorAdvisoryIndex.fingerprint(source));
            source.setApiKey("must-not-be-forwarded");assertThrows(IllegalArgumentException.class,()->VendorAdvisoryIndex.validate(source));
        }
        assertThrows(IllegalArgumentException.class,()->VendorAdvisoryIndex.validate(source("debian-tracker")));
        for(String address:List.of("https://example.invalid/feed?token=secret","https://user:secret@example.invalid/feed","https://example.invalid/a/../b","https://example.invalid/%2e%2e","http://example.invalid/feed")) {
            var source=source("ubuntu-usn");source.setUrl(address);assertThrows(IllegalArgumentException.class,()->VendorAdvisoryIndex.validate(source));
        }
    }
    @Test void redhatPathsAreStrictAndUnrelatedAdvisoryKindsDoNotBecomeSecurityRules() {
        String csv="\"2024/rhsa-2024_0001.json\",\"2026-10-01T00:00:00Z\"\n\"2024/rhba-2024_0002.json\",\"2026-10-01T00:00:00Z\"\n";
        var rows=VendorAdvisoryIndex.redhat(csv.getBytes(StandardCharsets.UTF_8),"https://example.invalid/csaf",Instant.EPOCH);
        assertEquals(1,rows.size());assertEquals("RHSA-2024:0001",rows.get(0).id());assertEquals("https://example.invalid/csaf/2024/rhsa-2024_0001.json",rows.get(0).address());
        for(String line:List.of("\"https://evil.invalid/doc\",\"2026-10-01T00:00:00Z\"", "\"2024/../rhsa-2024_0001.json\",\"2026-10-01T00:00:00Z\"",csv+csv))
            assertThrows(IllegalArgumentException.class,()->VendorAdvisoryIndex.redhat(line.getBytes(StandardCharsets.UTF_8),"https://example.invalid",Instant.EPOCH));
    }
    @Test void actualPublisherDiscoveryIndexesUseNativeIdsWithoutFollowingDocumentUrls() throws Exception {
        String configured=System.getenv("ALINKSEC_VENDOR_NATIVE_SAMPLES");assumeTrue(configured!=null);Path root=Path.of(configured);
        var redhat=VendorAdvisoryIndex.redhat(Files.readAllBytes(root.resolve("redhat-index.json")),VendorAdvisoryIndex.DEFAULTS.get("redhat-csaf"),Instant.now().minusSeconds(7*86_400));
        assertFalse(redhat.isEmpty());assertTrue(redhat.stream().allMatch(r->r.address().startsWith("https://security.access.redhat.com/data/csaf/v2/advisories/")));
        var microsoft=VendorAdvisoryIndex.microsoft(Files.readAllBytes(root.resolve("msrc-index.json")),VendorAdvisoryIndex.DEFAULTS.get("msrc-cvrf"),Instant.EPOCH);
        assertFalse(microsoft.isEmpty());assertTrue(microsoft.stream().allMatch(r->r.address().matches("https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/[0-9]{4}-[A-Z][a-z]{2}")));
        var ubuntu=VendorAdvisoryIndex.json(Files.readAllBytes(root.resolve("ubuntu-index.json"))).path("notices");assertEquals(1,ubuntu.size());
        assertTrue(ubuntu.get(0).path("id").asText().matches("USN-[0-9]+-[0-9]+"));
    }
}
