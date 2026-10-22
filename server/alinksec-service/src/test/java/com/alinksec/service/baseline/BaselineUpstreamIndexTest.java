package com.alinksec.service.baseline;

import com.alinksec.common.util.JsonUtils;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Instant;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class BaselineUpstreamIndexTest {
    final KeyPair key=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    final BaselineUpstreamProperties.Source source=new BaselineUpstreamProperties.Source();
    BaselineUpstreamIndexTest() throws Exception {
        source.setId("publisher");source.setName("Publisher");source.setUrl("https://updates.example.invalid/index.json");source.setPublicKey(Base64.getEncoder().encodeToString(key.getPublic().getEncoded()));source.setScopes(List.of("baseline:LINUX"));source.validate();
    }
    ObjectNode payload(){return (ObjectNode)JsonUtils.read(JsonUtils.write(Map.of("sourceId","publisher","sequence",1,"generatedAt",Instant.now().toString(),"expiresAt",Instant.now().plusSeconds(3600).toString(),"releases",List.of(Map.of("kind","baseline","code","LINUX","version","1","osType",1,"url","https://updates.example.invalid/artifacts/linux.json","sha256","a".repeat(64),"size",200,"status","active")))));}
    byte[] sign(byte[] payload)throws Exception{var signature=Signature.getInstance("Ed25519");signature.initSign(key.getPrivate());signature.update(payload);return JsonUtils.write(Map.of("formatVersion",1,"payload",Base64.getEncoder().encodeToString(payload),"signature",Base64.getEncoder().encodeToString(signature.sign()))).getBytes(StandardCharsets.UTF_8);}
    byte[] sign(ObjectNode doc)throws Exception{return sign(JsonUtils.write(doc).getBytes(StandardCharsets.UTF_8));}
    void invalid(ObjectNode doc)throws Exception{byte[] bytes=sign(doc);assertThrows(IllegalArgumentException.class,()->BaselineUpstreamIndex.verify(bytes,source,System.currentTimeMillis()));}
    @Test void exactSignatureScopeOriginAndExpiry()throws Exception{
        byte[] signed=sign(payload());assertEquals(1,BaselineUpstreamIndex.verify(signed,source,System.currentTimeMillis()).releases().size());
        var other=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();source.setPublicKey(Base64.getEncoder().encodeToString(other.getPublic().getEncoded()));assertThrows(IllegalArgumentException.class,()->BaselineUpstreamIndex.verify(signed,source,System.currentTimeMillis()));
        source.setPublicKey(Base64.getEncoder().encodeToString(key.getPublic().getEncoded()));
        for(String field:List.of("sourceId","sequence","expiresAt","generatedAt")){
            var doc=payload();switch(field){case "sourceId"->doc.put(field,"other");case "sequence"->doc.put(field,1.5);case "expiresAt"->doc.put(field,Instant.now().minusSeconds(1).toString());default->doc.put(field,Instant.now().plusSeconds(600).toString());}invalid(doc);
        }
        for(String url:List.of("http://updates.example.invalid/file","https://other.example.invalid/file","https://updates.example.invalid:444/file","https://user@updates.example.invalid/file","https://updates.example.invalid/file?secret=value","https://updates.example.invalid/file#fragment")){
            var doc=payload();((ObjectNode)doc.path("releases").get(0)).put("url",url);invalid(doc);
        }
        var doc=payload();((ObjectNode)doc.path("releases").get(0)).put("code","WINDOWS");invalid(doc);
        doc=payload();((ObjectNode)doc.path("releases").get(0)).put("size",2_097_153);invalid(doc);
        doc=payload();doc.put("unknown",true);invalid(doc);
        doc=payload();doc.withArray("releases").add(doc.path("releases").get(0).deepCopy());invalid(doc);
    }
    @Test void rejectsDuplicateFieldsTrailingTokensMalformedUtf8AndDeepStructures()throws Exception{
        String raw=JsonUtils.write(payload());
        for(String value:List.of(raw.replace("\"sequence\":1","\"sequence\":1,\"sequence\":2"),raw+" {}","[".repeat(20)+"0"+"]".repeat(20))){byte[] bytes=sign(value.getBytes(StandardCharsets.UTF_8));assertThrows(IllegalArgumentException.class,()->BaselineUpstreamIndex.verify(bytes,source,System.currentTimeMillis()));}
        byte[] malformed=sign(new byte[]{(byte)0xc3,0x28});assertThrows(IllegalArgumentException.class,()->BaselineUpstreamIndex.verify(malformed,source,System.currentTimeMillis()));
        byte[] signed=sign(payload());String envelope=new String(signed,StandardCharsets.UTF_8).replace("\"formatVersion\":1","\"formatVersion\":1,\"formatVersion\":1");byte[] duplicate=envelope.getBytes(StandardCharsets.UTF_8);assertThrows(IllegalArgumentException.class,()->BaselineUpstreamIndex.verify(duplicate,source,System.currentTimeMillis()));
    }
    @Test void invalidSourceConfigurationsFailBeforeNetwork(){
        source.setUrl("http://example.invalid/index");assertThrows(IllegalArgumentException.class,source::validate);
        source.setUrl("https://example.invalid/index?token=private");assertThrows(IllegalArgumentException.class,source::validate);
        source.setUrl("https://example.invalid/index");source.setScopes(List.of("baseline:LINUX","baseline:LINUX"));assertThrows(IllegalArgumentException.class,source::validate);
    }
}
