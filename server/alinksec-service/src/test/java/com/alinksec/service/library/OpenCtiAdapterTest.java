package com.alinksec.service.library;

import com.alinksec.common.util.JsonUtils;
import com.fasterxml.jackson.databind.node.*;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class OpenCtiAdapterTest {
    static final String SHA="a".repeat(64),ID="11111111-1111-4111-8111-111111111111";
    static final Instant NOW=Instant.parse("2026-10-23T00:00:00Z");
    LibraryProperties.Source source(){var s=new LibraryProperties.Source();s.setType("opencti");s.setUrl("https://cti.example.invalid/prefix/graphql");s.setApiKey("private-integration-token");s.setOpenctiTag("alinksec:malicious-file");return s;}
    OpenCtiAdapter.Config config(){return new OpenCtiAdapter.Config("","","alinksec:malicious-file",75,4,"");}
    ObjectNode node(){
        var n=JsonUtils.mapper().createObjectNode();n.put("id",ID).put("standard_id","indicator--"+ID).put("name","Approved file").put("created_at","2026-01-01T00:00:00Z")
                .put("modified","2026-10-01T00:00:00Z").put("pattern_type","stix").put("pattern_version","2.1").put("pattern","[file:hashes.'SHA-256' = '"+SHA+"']")
                .put("revoked",false).put("confidence",75).put("valid_from","2026-10-01T00:00:00Z").putNull("valid_until").put("x_opencti_detection",true);
        n.putArray("objectLabel").addObject().put("value","alinksec:malicious-file");return n;
    }
    String decision(ObjectNode n){return OpenCtiAdapter.indicator(n,config()).reasonAt(NOW);}
    @Test void onlyCompleteSingleSha256EqualitiesAreDetectionPredicates(){
        for(String pattern:List.of("[file:hashes.'SHA-256' = '"+SHA+"']","[ file:hashes.'SHA-256'='"+SHA.toUpperCase(Locale.ROOT)+"' ]","[\nfile:hashes.'SHA-256' = '"+SHA+"'\n]")){
            var n=node().put("pattern",pattern);var result=OpenCtiAdapter.indicator(n,config());assertEquals("included",result.reasonAt(NOW));assertEquals(SHA,result.hash());
        }
        for(String pattern:List.of("[file:hashes.'SHA-256' = '"+SHA+"'] OR [file:size = 1]","[file:hashes.'SHA-256' = '"+SHA+"' AND file:size = 1]","[file:hashes.'SHA-256' != '"+SHA+"']","[file:hashes.'SHA-256' = '"+SHA+"'] START t'2026-01-01T00:00:00Z' STOP t'2026-12-01T00:00:00Z'","garbage '"+SHA+"'","[file:hashes.'MD5' = '"+SHA+"']","[file:hashes.'SHA-256' = '"+SHA.substring(1)+"']"))
            assertEquals("unsupported_pattern",decision(node().put("pattern",pattern)),pattern);
        assertEquals("unsupported_pattern",decision(node().put("pattern_type","yara")));
        assertEquals("unsupported_version",decision(node().put("pattern_version","future")));
    }
    @Test void reviewLifecycleAndConfidenceAreIndependentRequiredGates(){
        assertEquals("revoked",decision(node().put("revoked",true)));
        assertEquals("detection_disabled",decision(node().put("x_opencti_detection",false)));
        assertEquals("detection_disabled",decision(node().putNull("x_opencti_detection")));
        assertEquals("confidence",decision(node().put("confidence",74)));
        assertEquals("confidence",decision(node().putNull("confidence")));
        var n=node();n.putArray("objectLabel").addObject().put("value","unreviewed");assertEquals("not_approved",decision(n));
        assertEquals("not_approved",decision(node().putNull("objectLabel")));
        assertEquals("future",decision(node().put("valid_from","2026-10-24T00:00:00Z")));
        assertEquals("expired",decision(node().put("valid_until",NOW.toString())));
        assertEquals("missing_validity",decision(node().putNull("valid_from")));
        assertEquals("included",decision(node()));
    }
    @Test void malformedTypesFieldsDatesAndIdentityAbortTheCollection(){
        List<ObjectNode> invalid=List.of(node().put("revoked","false"),node().put("confidence",75.5),node().put("confidence",101),node().put("x_opencti_detection","true"),node().put("id","not-an-id"),node().put("standard_id","malware--"+ID),node().put("valid_until","yesterday"),node().put("valid_until","2020-01-01T00:00:00Z"),node().put("created_at","2026-01-01"));
        for(var n:invalid)assertThrows(OpenCtiAdapter.Failure.class,()->decision(n));
        var missing=node();missing.remove("revoked");assertThrows(OpenCtiAdapter.Failure.class,()->decision(missing));
        var labels=node();labels.set("objectLabel",JsonUtils.mapper().createArrayNode().add("tag"));assertThrows(OpenCtiAdapter.Failure.class,()->decision(labels));
    }
    @Test void expiryDoesNotRoundAnIndicatorDeadlineEarlier(){
        var n=node().put("valid_until","2026-10-23T00:00:00.000000001Z");var r=OpenCtiAdapter.indicator(n,config());
        assertEquals("included",r.reasonAt(NOW));assertEquals(NOW.toEpochMilli()+1,r.expiresAt());assertEquals("expired",r.reasonAt(NOW.plusNanos(1)));
    }
    @Test void strictJsonRejectsDuplicateTrailingMalformedAndDeepInputs(){
        for(byte[] bytes:List.of("{\"data\":{},\"data\":{}}".getBytes(StandardCharsets.UTF_8),"{} {}".getBytes(StandardCharsets.UTF_8),new byte[]{'{','"','x','"',':','"',(byte)0xff,'"','}'},("{\"nested\":"+"[".repeat(25)+"0"+"]".repeat(25)+"}").getBytes(StandardCharsets.UTF_8)))
            assertThrows(OpenCtiAdapter.Failure.class,()->OpenCtiAdapter.parse(bytes));
    }
    @Test void scopeFingerprintPinsPolicyButAllowsSameAccountKeyRotation(){
        var s=source();String original=OpenCtiAdapter.fingerprint(s);s.setApiKey("rotated-private-key");s.setEnabled(true);s.setIntervalMs(600_000);assertEquals(original,OpenCtiAdapter.fingerprint(s));
        s.setOpenctiMinConfidence(76);assertNotEquals(original,OpenCtiAdapter.fingerprint(s));s.setOpenctiMinConfidence(75);
        s.setOpenctiTag("another:review");assertNotEquals(original,OpenCtiAdapter.fingerprint(s));s.setOpenctiTag("alinksec:malicious-file");
        s.setOpenctiSeverity(3);assertNotEquals(original,OpenCtiAdapter.fingerprint(s));s.setOpenctiSeverity(4);
        s.setUrl("https://another.example.invalid/graphql");assertNotEquals(original,OpenCtiAdapter.fingerprint(s));
    }
    @Test void credentialsAndDestinationsHaveNoQueryOrRedirectEscapeHatch(){
        for(String url:List.of("http://remote.example.invalid/graphql","https://user:secret@cti.example.invalid/graphql","https://cti.example.invalid/graphql?token=secret","https://cti.example.invalid/graphql#fragment","https://cti.example.invalid/api","https://cti.example.invalid/prefix/../graphql","https://cti.example.invalid/%2e%2e/graphql")){
            var s=source();s.setUrl(url);assertFalse(OpenCtiAdapter.configurationIssue(s).isEmpty());
        }
        var s=source();s.setApiKey("secret\r\nX-Key: bad");assertFalse(OpenCtiAdapter.configurationIssue(s).isEmpty());
        s=source();s.setApiKey("");assertFalse(OpenCtiAdapter.configurationIssue(s).isEmpty());
        s=source();s.setOpenctiTag("");assertFalse(OpenCtiAdapter.configurationIssue(s).isEmpty());
        assertEquals("",OpenCtiAdapter.configurationIssue(source()));
    }
}
