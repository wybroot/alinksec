package com.alinksec.bootstrap;

import com.alinksec.common.util.*;
import com.alinksec.gateway.rest.*;
import com.alinksec.service.config.*;
import com.alinksec.service.library.*;
import com.alinksec.service.scan.VulnMatchService;
import com.alinksec.service.virus.VirusDbService;
import com.fasterxml.jackson.databind.JsonNode;
import com.zaxxer.hikari.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/** Opt-in real public HTTPS; no mirror, fixture transport, TLS override or fallback. */
@EnabledIfEnvironmentVariable(named="ALINKSEC_EXTERNAL_EVIDENCE", matches=".+")
class VendorAdvisoryLiveIntegrationTest {
    @TempDir Path root;
    static final String SECRET="public-advisory-test-only-secret-32-bytes";

    @ParameterizedTest(name="{0}")
    @CsvSource({
        "ubuntu-usn, https://ubuntu.com/security/notices/USN-6727-1.json",
        "debian-tracker, https://security-tracker.debian.org/tracker/data/json",
        "redhat-csaf, https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_0001.json",
        "msrc-cvrf, https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2024-Apr"
    })
    @Timeout(120)
    void actualPublisherSyncCommitsRawBytesAndServesProtectedApis(String type,String address) throws Exception {
        Path evidence=Path.of(System.getenv("ALINKSEC_EXTERNAL_EVIDENCE")).resolve("publishers");
        Files.createDirectories(evidence);
        var config=new HikariConfig();config.setJdbcUrl("jdbc:sqlite:"+root.resolve("acceptance.db"));
        config.setMaximumPoolSize(2);config.setMinimumIdle(1);
        config.addDataSourceProperty("transaction_mode","IMMEDIATE");
        config.addDataSourceProperty("busy_timeout",5000);config.addDataSourceProperty("foreign_keys",true);
        try(var pool=new HikariDataSource(config)) {
            new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor().postProcessAfterInitialization(pool,"dataSource");
            var jdbc=new JdbcTemplate(pool);var props=new LibraryProperties();props.setWorkDir(root.resolve("work").toString());
            var source=new LibraryProperties.Source();source.setId("public-"+type);source.setType(type);
            source.setUrl(address);source.setEnabled(true);source.setVendorPackages(List.of("openssl","curl","expat"));
            props.setSources(List.of(source));var platform=new AlinkSecProperties();platform.getDatabase().setType("sqlite");
            try(var files=new ClosingFiles(props,platform)) {
                var catalog=new LibraryCatalog(jdbc,props,files,new DatabaseDialect(platform),new DataSourceTransactionManager(pool));
                var schedules=new LibrarySchedule(props,jdbc);var limits=new VendorAdvisoryProperties();limits.setDocumentsPerSync(1);
                var sync=new LibrarySyncService(props,catalog,mock(VirusDbService.class),new FeedDownload(files,props),jdbc,mock(VulnMatchService.class),schedules,limits);
                try {
                    sync.validate();sync.sync(source);
                    assertEquals("success",jdbc.queryForObject("SELECT status FROM t_security_feed_state WHERE source_id=?",String.class,source.getId()),type);
                    assertEquals(1,sync.history(source.getId()).size());
                    var archive=jdbc.queryForMap("SELECT * FROM t_vendor_document WHERE source_id=?",source.getId());
                    assertEquals(address,archive.get("origin"));assertEquals("official_https",archive.get("origin_kind"));
                    assertEquals(1,((Number)archive.get("current_version")).intValue());
                    String id=archive.get("id").toString();byte[] raw=sync.nativeAdvisories(source.getId()).raw(source.getId(),id);
                    assertTrue(raw.length>0 && raw.length<=32<<20);assertEquals(raw.length,((Number)archive.get("size_bytes")).intValue());
                    String rawSHA=digest(raw);assertEquals(rawSHA,archive.get("sha256"));
                    // Retain exactly the bytes accepted by the production downloader, not another HTTP fetch.
                    Files.write(evidence.resolve(type+".raw"),raw);
                    var parsed=VendorAdvisoryAdapter.parse(source,raw);var expected=new TreeSet<String>();
                    for(var cve:parsed.cves())expected.add(cve.path("cve_id").asText());
                    assertFalse(expected.isEmpty(),type);
                    var committed=new TreeSet<>(jdbc.queryForList("SELECT cve_id FROM t_security_cve WHERE source_id=?",String.class,source.getId()));
                    assertEquals(expected,committed);assertEquals(expected.size(),((Number)archive.get("cve_count")).intValue());
                    assertEquals(expected.size(),jdbc.queryForObject("SELECT count(*) FROM t_vendor_contribution WHERE source_id=? AND raw_document_id=?",Integer.class,source.getId(),id));
                    var holder=mock(JwtSecretHolder.class);when(holder.secret()).thenReturn(SECRET);
                    MockMvc mvc=MockMvcBuilders.standaloneSetup(new LibraryController(sync,catalog,props,schedules))
                            .setControllerAdvice(new RestExceptionHandler()).addInterceptors(new JwtAuthInterceptor(holder)).build();
                    String token=JwtUtil.sign(SECRET,Map.of("uid",1,"username","isolated-public-test","role","admin"),3600);
                    String path="/api/libraries/sources/"+source.getId()+"/advisories/"+id;
                    assertEquals(401,mvc.perform(get(path+"/raw")).andReturn().getResponse().getStatus());
                    var response=mvc.perform(get(path+"/raw").header("Authorization","Bearer "+token)).andReturn().getResponse();
                    assertEquals(200,response.getStatus());assertArrayEquals(raw,response.getContentAsByteArray());
                    assertEquals(rawSHA,response.getHeader("X-Content-SHA256"));assertEquals("no-store",response.getHeader("Cache-Control"));
                    String first=expected.first();
                    var declaration=mvc.perform(get("/api/libraries/cves/"+first+"/declarations").header("Authorization","Bearer "+token)).andReturn().getResponse();
                    assertEquals(200,declaration.getStatus());
                    JsonNode body=JsonUtils.read(declaration.getContentAsString(StandardCharsets.UTF_8));
                    assertTrue(body.toString().contains(source.getId()));
                    int rules=0;
                    for(String cve:expected) {
                        var row=jdbc.queryForMap("SELECT document,provenance FROM t_security_cve WHERE source_id=? AND cve_id=?",source.getId(),cve);
                        JsonNode provenance=JsonUtils.read(row.get("provenance").toString());
                        assertEquals("native_vendor_advisory",provenance.path("ingestion").asText());
                        assertFalse(provenance.path("signature_verified").asBoolean());
                        assertEquals(rawSHA,provenance.path("raw_documents").get(0).path("sha256").asText());
                        for(var rule:JsonUtils.read(row.get("document").toString()).path("affected")) {
                            rules++;assertTrue(rule.path("vrange").asText().startsWith("="));assertEquals("",rule.path("fixed_version").asText());
                        }
                    }
                    if(Set.of("debian-tracker","redhat-csaf","msrc-cvrf").contains(type))assertEquals(0,rules,"No implicit binary/product mapping");
                    Files.writeString(evidence.resolve(type+".json"),JsonUtils.write(Map.ofEntries(
                            Map.entry("format",type),Map.entry("url",address),Map.entry("capturedAt",Instant.now().toString()),
                            Map.entry("rawFile",type+".raw"),Map.entry("bytes",raw.length),Map.entry("sha256",rawSHA),
                            Map.entry("documentId",parsed.id()),Map.entry("cveCount",expected.size()),Map.entry("cveIds",expected),Map.entry("exactVersionRules",rules),
                            Map.entry("cveSetSHA256",digest(String.join("\n",expected).getBytes(StandardCharsets.UTF_8))),
                            Map.entry("originKind","official_https"),Map.entry("database","isolated_sqlite"),
                            Map.entry("protectedRawApiVerified",true),Map.entry("declarationApiVerified",true),
                            Map.entry("publisherSignatureVerified",false),Map.entry("liveHostApplicabilityVerified",false)))+"\n");
                } finally {sync.close();}
            }
        }
    }
    static String digest(byte[] raw) throws Exception {return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    // LibraryFiles has a lifecycle close method, but deliberately does not expose AutoCloseable in production.
    static final class ClosingFiles extends LibraryFiles implements AutoCloseable {
        ClosingFiles(LibraryProperties props,AlinkSecProperties platform){super(props,platform);}
    }
}
