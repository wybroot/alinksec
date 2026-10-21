package com.alinksec.service.baseline;

import org.junit.jupiter.api.Test;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import static org.junit.jupiter.api.Assertions.*;

class ScapPackageTest {
    private static final String MANIFEST="""
        {"schemaVersion":1,"code":"TEST","version":"1","name":"Transport boundary","osType":1,
        "osVersionPattern":".*","benchmarkFile":"test.xml","benchmarkId":"xccdf_org.alinksec_benchmark_test","profileId":"xccdf_org.alinksec_profile_test"}
        """;
    // Structural fixtures test the import boundary; actual SCAP schema and
    // OVAL semantics are checked by the pinned native interpreter on three OSs.
    private static final String XML="""
        <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_org.alinksec_benchmark_test"><Profile id="xccdf_org.alinksec_profile_test"/><Rule id="xccdf_org.alinksec_rule_test"><title>Test</title></Rule></Benchmark>
        """;
    byte[] archive(String xml,String manifest,Map<String,String> extra) throws Exception {
        try (var out=new ByteArrayOutputStream();var zip=new ZipOutputStream(out,StandardCharsets.UTF_8)) {
            var files=new java.util.LinkedHashMap<String,String>();files.put("alinksec-scap.json",manifest);files.put("test.xml",xml);files.putAll(extra);
            for (var file:files.entrySet()) {zip.putNextEntry(new ZipEntry(file.getKey()));zip.write(file.getValue().getBytes(StandardCharsets.UTF_8));zip.closeEntry();}
            zip.finish();return out.toByteArray();
        }
    }
    @Test void normalizesReviewedArchiveBeforeDeliveryAndKeepsOriginalSourceDigest() throws Exception {
        byte[] source=archive(XML,MANIFEST,Map.of());
        var content=ScapPackage.read(source);
        assertEquals(ScapPackage.digest(source),content.sourceSha256());
        assertEquals(1,content.rules().size());
        assertArrayEquals(content.archive(),ScapPackage.read(content.archive()).archive());
        assertEquals(content.sha256(),ScapPackage.read(content.archive()).sha256());
        assertEquals("xccdf_org.alinksec_profile_test",content.manifest().path("profileId").asText());
    }
    @Test void rejectsExecutableRemoteOrAmbiguousContentBeforeNativeExecution() throws Exception {
        for (String invalid:java.util.List.of(
                "<!DOCTYPE Benchmark [<!ENTITY x SYSTEM 'file:///etc/shadow'>]>"+XML,
                XML.replace("<title>Test</title>","<fix system='urn:xccdf:fix:script:sh'>touch /tmp/must-not-exist</fix>"),
                XML.replace("<title>Test</title>","<check system='http://open-scap.org/page/SCE'><check-content-ref href='command.sh'/></check>"),
                XML.replace("<title>Test</title>","<shellcommand_test/>"),
                XML.replace("<title>Test</title>","<check system='http://oval.mitre.org/XMLSchema/oval-definitions-5'><check-content-ref href='https://example.invalid/checks.xml'/></check>"),
                XML.replace("<title>Test</title>","<check system='http://oval.mitre.org/XMLSchema/oval-definitions-5'><check-content-ref href='missing.xml'/></check>"),
                XML.replace("<title>Test</title>","<xi:include xmlns:xi='http://www.w3.org/2001/XInclude' href='test.xml'/>"),
                XML.replace("<title>Test</title>","<title xml:base='https://example.invalid/'>Test</title>"),
                XML.replace("</Benchmark>","<Rule id='xccdf_org.alinksec_rule_test'/></Benchmark>"),
                XML.replace("profile_test","profile_other"))) {
            byte[] data=archive(invalid,MANIFEST,Map.of());assertThrows(IllegalArgumentException.class,()->ScapPackage.read(data));
        }
        for (String name:java.util.List.of("../outside.xml","/absolute.xml","nested/../outside.xml","script.sh")) {
            byte[] data=archive(XML,MANIFEST,Map.of(name,"x"));assertThrows(IllegalArgumentException.class,()->ScapPackage.read(data));
        }
        byte[] duplicate=archive(XML,MANIFEST.replace("\"schemaVersion\":1","\"schemaVersion\":1,\"schemaVersion\":1"),Map.of());
        assertThrows(IllegalArgumentException.class,()->ScapPackage.read(duplicate));
    }
    @Test void acceptsActualNativeDataStreamAndItsCatalogReferences() throws Exception {
        String path=System.getenv("ALINKSEC_SCAP_FIXTURE_ZIP");
        org.junit.jupiter.api.Assumptions.assumeTrue(path!=null&&!path.isBlank(),"requires real native standards fixture");
        var content=ScapPackage.read(Files.readAllBytes(Path.of(path)));
        assertEquals(5,content.rules().size());assertEquals(2,content.profiles().size());
        assertEquals("xccdf_org.alinksec_profile_native",content.manifest().path("profileId").asText());
        assertArrayEquals(content.archive(),ScapPackage.read(content.archive()).archive());
    }
}
