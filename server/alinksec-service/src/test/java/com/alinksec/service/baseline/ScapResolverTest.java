package com.alinksec.service.baseline;

import com.alinksec.common.util.JsonUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/** Calls the actual production resolver. The platform jobs consume this exact
 * resolved Benchmark and independently exercise native OVAL probes and SCC. */
class ScapResolverTest {
    @Test void resolvesInheritedSelectionsWithNativeOpenScapAndPreservesSource() throws Exception {
        String fixture=System.getenv("ALINKSEC_SCAP_FIXTURE_ZIP");
        org.junit.jupiter.api.Assumptions.assumeTrue(fixture!=null&&System.getenv("ALINKSEC_SCAP_RESOLVE_OUTPUT")!=null,"requires native standard resolver job");
        byte[] archive=Files.readAllBytes(Path.of(fixture));
        var source=ScapPackage.read(archive);
        var resolver=new ScapResolver();
        var resolved=resolver.resolve(source);
        assertEquals(source.manifest(),resolved.content().manifest());
        assertEquals(source.rules(),resolved.content().rules());
        assertArrayEquals(archive,Files.readAllBytes(Path.of(fixture)));
        assertNotEquals(source.sha256(),resolved.content().sha256());
        var files=ScapResolver.files(resolved.content().archive());
        Element benchmark=ScapResolver.benchmark(ScapPackage.xml(files.get("native-ds.xml")));
        assertTrue(Set.of("true","1").contains(benchmark.getAttribute("resolved")));
        Element profile=ScapResolver.elements(benchmark).stream().filter(e->e.getAttribute("id").equals(source.manifest().path("profileId").asText())).findFirst().orElseThrow();
        Map<String,String> selected=new TreeMap<>();
        for(Element element:ScapResolver.elements(profile)) {
            assertFalse(element.hasAttribute("extends"));
            if(element.getLocalName().equals("select"))assertNull(selected.put(element.getAttribute("idref"),element.getAttribute("selected")),"duplicate inherited selection");
        }
        assertEquals(Map.of("xccdf_org.alinksec_rule_external","true","xccdf_org.alinksec_rule_failure","true","xccdf_org.alinksec_rule_compound","true","xccdf_org.alinksec_rule_platform","true","xccdf_org.alinksec_rule_unselected","false"),selected);
        assertTrue(ScapResolver.elements(profile).stream().anyMatch(e->e.getLocalName().equals("set-value")&&e.getAttribute("idref").equals("xccdf_org.alinksec_value_expected")&&e.getTextContent().equals("observed-native")));
        var provenance=JsonUtils.read(resolved.provenance());
        assertTrue(provenance.path("resolver").asText().startsWith("OpenSCAP command line tool (oscap) "));
        assertEquals(source.sha256(),provenance.path("sourceCanonicalSha256").asText());
        assertEquals(resolved.content().sha256(),resolver.resolve(source).content().sha256(),"same source must resolve deterministically");
        Path output=Path.of(System.getenv("ALINKSEC_SCAP_RESOLVE_OUTPUT"));Files.createDirectories(output);
        Files.write(output.resolve("benchmark.xml"),ScapResolver.serialize(benchmark));
        Files.write(output.resolve("source.zip"),archive);
        Files.write(output.resolve("resolved.zip"),resolved.content().archive());
        Files.writeString(output.resolve("provenance.json"),resolved.provenance()+"\n",StandardCharsets.UTF_8);
        // A missing parent cannot silently become a default or empty Profile.
        var broken=ScapResolver.files(source.archive());
        broken.put("native-ds.xml",new String(broken.get("native-ds.xml"),StandardCharsets.UTF_8).replace("extends=\"xccdf_org.alinksec_profile_base\"","extends=\"xccdf_org.alinksec_profile_absent\"").getBytes(StandardCharsets.UTF_8));
        assertThrows(IllegalArgumentException.class,()->resolver.resolve(ScapPackage.read(ScapResolver.archive(broken))));
    }
}
