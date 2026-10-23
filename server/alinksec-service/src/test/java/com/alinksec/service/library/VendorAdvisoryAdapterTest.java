package com.alinksec.service.library;

import com.alinksec.common.util.JsonUtils;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class VendorAdvisoryAdapterTest {
    private static LibraryProperties.Source source(String type) {
        var source = new LibraryProperties.Source();
        source.setId("native-fixture"); source.setType(type);
        source.setVendorPackages(List.of("openssl","curl","expat"));
        var mapping = new LibraryProperties.VendorProduct();
        mapping.setProductId("rhel-product"); mapping.setDistroId("rhel"); mapping.setDistroVersion("9.3");
        source.setVendorProducts(List.of(mapping));
        return source;
    }
    private static byte[] bytes(JsonNode node) { return JsonUtils.write(node).getBytes(StandardCharsets.UTF_8); }
    private static ObjectNode csaf(String status) {
        ObjectNode root = (ObjectNode) JsonUtils.read("""
            {"document":{"csaf_version":"2.0","title":"Fixture advisory","tracking":{"id":"RHSA-2024:0001","version":"1","current_release_date":"2024-01-02T07:46:50Z"}},
             "product_tree":{"branches":[{"product":{"product_id":"binary","name":"thunderbird-0:115.6.0-1.el9_3.x86_64","product_identification_helper":{"purl":"pkg:rpm/redhat/thunderbird@115.6.0-1.el9_3?arch=x86_64"}}}],
               "relationships":[{"category":"default_component_of","product_reference":"binary","relates_to_product_reference":"rhel-product","full_product_name":{"product_id":"installed"}}]},
             "vulnerabilities":[{"cve":"CVE-2023-6856","product_status":{},"scores":[{"cvss_v3":{"baseScore":8.8}}]}]}
            """);
        ((ObjectNode) root.path("vulnerabilities").get(0).path("product_status"))
                .set(status, JsonUtils.mapper().createArrayNode().add("installed"));
        return root;
    }
    @Test void fixedOnlyCsafDoesNotInventEarlierAffectedVersionsOrRepairTargets() throws Exception {
        var result = VendorAdvisoryAdapter.parse(source("redhat-csaf"),bytes(csaf("fixed")));
        JsonNode rule = result.cves().get(0).path("affected").get(0);
        assertEquals("=0:115.6.0-1.el9_3",rule.path("vrange").asText());
        assertEquals("not_affected",rule.path("evidence").path("assessment").asText());
        assertEquals("",rule.path("fixed_version").asText());
        assertEquals("9.3",rule.path("distro_version").asText());
        assertEquals("x86_64",rule.path("architecture").asText());
    }
    @Test void comparableCsafRequiresExplicitPlatformAndConsistentBinaryIdentity() throws Exception {
        var source=source("redhat-csaf");var input=csaf("known_affected");
        assertEquals("affected",VendorAdvisoryAdapter.parse(source,bytes(input)).cves().get(0)
                .path("affected").get(0).path("evidence").path("assessment").asText());
        source.setVendorProducts(List.of());
        assertTrue(VendorAdvisoryAdapter.parse(source,bytes(input)).cves().get(0).path("affected").isEmpty());
        source=source("redhat-csaf");
        ((ObjectNode)input.path("product_tree").path("branches").get(0).path("product")
                .path("product_identification_helper")).put("purl","pkg:rpm/redhat/thunderbird@115.6.0-1.el9_3?arch=aarch64");
        assertTrue(VendorAdvisoryAdapter.parse(source,bytes(input)).cves().get(0).path("affected").isEmpty());
        var original=csaf("known_affected");
        ((ObjectNode)original.path("product_tree").path("relationships").get(0)).put("category","external_component_of");
        assertTrue(VendorAdvisoryAdapter.parse(source,bytes(original)).cves().get(0).path("affected").isEmpty());
    }
    @Test void debianSourceClaimsNeverBecomeBinaryFindingsOrPatchTargets() throws Exception {
        var input=JsonUtils.read("""
            {"openssl":{"CVE-2024-1234":{"description":"Fixture","releases":{
              "bookworm":{"status":"resolved","fixed_version":"0","urgency":"unimportant"},
              "trixie":{"status":"open","urgency":"high"}}}},
             "unselected":{"CVE-2024-5555":{"releases":{}}}}
            """);
        var result=VendorAdvisoryAdapter.parse(source("debian-tracker"),bytes(input));
        assertEquals(1,result.cves().size());var document=result.cves().get(0);
        assertTrue(document.path("affected").isEmpty());
        assertEquals("source",document.path("vendor_advisories").get(0).path("package_scope").asText());
        assertEquals("0",document.path("vendor_advisories").get(0).path("fixed_version").asText());
        assertEquals("open",document.path("vendor_advisories").get(1).path("status").asText());
    }
    @Test void ubuntuNoticeDoesNotCrossApplyPackageFixesToEveryCveOrArchitecture() throws Exception {
        var input=JsonUtils.read("""
            {"id":"USN-6727-1","title":"Fixture","published":"2024-04-10T13:40:08.464696",
             "cves_ids":["CVE-2023-5388"],"release_packages":{"jammy":[
               {"name":"nss","version":"2:3.98-0ubuntu0.22.04.1","is_source":true},
               {"name":"libnss3","version":"2:3.98-0ubuntu0.22.04.1","is_source":false}]}}
            """);
        var result=VendorAdvisoryAdapter.parse(source("ubuntu-usn"),bytes(input));
        assertTrue(result.cves().get(0).path("affected").isEmpty());
        var packages=result.cves().get(0).path("vendor_advisories").get(0).path("packages");
        assertEquals("source",packages.get(0).path("package_scope").asText());
        assertEquals("binary",packages.get(1).path("package_scope").asText());
        assertEquals("2024-04-10T13:40:08.464696Z",result.updated().toString());
    }
    @Test void microsoftKbAndBuildReferencesDoNotProveInstalledWindowsApplicability() throws Exception {
        var input=JsonUtils.read("""
            {"DocumentTitle":{"Value":"Fixture"},"DocumentTracking":{"Identification":{"ID":{"Value":"2024-Apr"}},
              "Version":"1.0","CurrentReleaseDate":"2024-04-09T07:00:00"},
             "Vulnerability":[{"CVE":"CVE-2024-1234","Title":{"Value":"Fixture"},
               "CVSSScoreSets":[{"BaseScore":8.8}],"ProductStatuses":[{"Type":3,"ProductID":["123"]}],
               "Remediations":[{"Type":2,"Description":{"Value":"5030001"},"ProductID":["123"],
                 "FixedBuild":"10.0.19045.1"}]}]}
            """);
        var result=VendorAdvisoryAdapter.parse(source("msrc-cvrf"),bytes(input));
        var document=result.cves().get(0);assertTrue(document.path("affected").isEmpty());
        assertEquals(8.8,document.path("cvss").asDouble());
        var fact=document.path("vendor_advisories").get(0);
        assertEquals("5030001",fact.path("remediations").get(0).path("description").asText());
        assertEquals("123",fact.path("product_statuses").get(0).path("products").get(0).asText());
    }
    @Test void invalidEncodingDuplicateFieldsTrailingDataDepthAndVendorIdentityAreRejected() {
        var source=source("redhat-csaf");
        for (byte[] invalid:List.of(
                "{\"document\":{},\"document\":{}}".getBytes(StandardCharsets.UTF_8),
                (JsonUtils.write(csaf("fixed"))+" {}").getBytes(StandardCharsets.UTF_8),
                ("{\"x\":"+"[".repeat(45)+"0"+"]".repeat(45)+"}").getBytes(StandardCharsets.UTF_8),
                new byte[]{'{','"','x','"',':','"',(byte)0xc3,0x28,'"','}'},
                "{}".getBytes(StandardCharsets.UTF_8))) {
            assertThrows(Exception.class,()->VendorAdvisoryAdapter.parse(source,invalid));
        }
        var input=csaf("fixed");((ObjectNode)input.path("document").path("tracking")).put("id","OTHER-1");
        assertThrows(IllegalArgumentException.class,()->VendorAdvisoryAdapter.parse(source,bytes(input)));
    }
    @Test void actualPublisherSamplesParseWithoutInventingOlderVersionRanges() throws Exception {
        String configured=System.getenv("ALINKSEC_VENDOR_NATIVE_SAMPLES");assumeTrue(configured!=null);
        Path root=Path.of(configured);
        var evidence=JsonUtils.mapper().createArrayNode();
        for (String type:VendorAdvisoryAdapter.TYPES) {
            Path file=root.resolve(type+".json");assertTrue(Files.isRegularFile(file),type);
            var result=VendorAdvisoryAdapter.parse(source(type),Files.readAllBytes(file));
            assertFalse(result.cves().isEmpty(),type);
            for(var document:result.cves())for(var rule:document.path("affected")) {
                assertTrue(rule.path("vrange").asText().startsWith("="));
                assertEquals("",rule.path("fixed_version").asText());
            }
            evidence.addObject().put("format",type).put("documentId",result.id())
                    .put("publisher",result.publisher()).put("cveCount",result.cves().size())
                    .put("sourceBytes",Files.size(file));
        }
        Files.writeString(root.resolve("parsed-evidence.json"),JsonUtils.write(evidence));
    }
}
