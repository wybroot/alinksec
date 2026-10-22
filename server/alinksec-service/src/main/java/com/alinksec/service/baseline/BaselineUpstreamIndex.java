package com.alinksec.service.baseline;

import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.databind.*;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.*;
import java.security.Signature;
import java.time.Instant;
import java.util.*;

/** A signature authenticates exact payload bytes, never a reserialized JSON object. */
public record BaselineUpstreamIndex(long sequence,String payloadHash,long expiresAt,List<Release> releases) {
    public static final int MAX_ENVELOPE=384*1024,MAX_PAYLOAD=256*1024;
    private static final ObjectMapper JSON=new ObjectMapper(JsonFactory.builder()
            .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(16).maxStringLength(360_000).maxNumberLength(20).build())
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build())
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    public record Release(String kind,String code,String version,int osType,String url,String sha256,long size,String status) {}
    public static BaselineUpstreamIndex verify(byte[] envelope,BaselineUpstreamProperties.Source source,long now) {
        try {
            require(envelope.length>0&&envelope.length<=MAX_ENVELOPE);
            JsonNode outer=parse(envelope);fields(outer,"formatVersion","payload","signature");
            require(outer.path("formatVersion").isInt()&&outer.path("formatVersion").intValue()==1);
            byte[] payload=decode(text(outer,"payload",360_000)),signature=decode(text(outer,"signature",128));
            require(payload.length>0&&payload.length<=MAX_PAYLOAD&&signature.length==64);
            Signature verifier=Signature.getInstance("Ed25519");verifier.initVerify(source.key());verifier.update(payload);require(verifier.verify(signature));
            JsonNode doc=parse(payload);fields(doc,"sourceId","sequence","generatedAt","expiresAt","releases");
            require(text(doc,"sourceId",64).equals(source.getId()));
            require(doc.path("sequence").isIntegralNumber()&&doc.path("sequence").canConvertToLong());long seq=doc.path("sequence").longValue();require(seq>0);
            long generated=Instant.parse(text(doc,"generatedAt",40)).toEpochMilli(),expires=Instant.parse(text(doc,"expiresAt",40)).toEpochMilli();
            require(generated<=now+300_000&&generated>=now-2_592_000_000L&&expires>now&&expires>generated&&expires-generated<=2_592_000_000L);
            JsonNode entries=doc.path("releases");require(entries.isArray()&&entries.size()<=64);
            var releases=new ArrayList<Release>();var seen=new HashSet<String>();URI origin=source.address();
            for(JsonNode entry:entries){
                fields(entry,"kind","code","version","osType","url","sha256","size","status");
                String kind=text(entry,"kind",8),code=text(entry,"code",256),version=text(entry,"version",256),url=text(entry,"url",1024),hash=text(entry,"sha256",64),status=text(entry,"status",16);
                require(source.getScopes().contains(kind+":"+code)&&code.matches("[A-Za-z0-9][A-Za-z0-9_.:-]*")&&version.matches("[A-Za-z0-9][A-Za-z0-9_.:-]*")&&seen.add(kind+":"+code+":"+version));
                require(entry.path("osType").isInt()&&Set.of(1,2).contains(entry.path("osType").intValue()));
                require(entry.path("size").isIntegralNumber()&&entry.path("size").canConvertToLong());long size=entry.path("size").longValue();
                require(size>0&&size<=ScapPackage.MAX_ARCHIVE&&ScapStore.hash(hash)&&Set.of("active","withdrawn").contains(status));
                URI artifact=com.alinksec.service.library.FeedDownload.validateAddress(url);
                require(artifact.getQuery()==null&&origin.getScheme().equals(artifact.getScheme())&&origin.getHost().equalsIgnoreCase(artifact.getHost())&&port(origin)==port(artifact));
                releases.add(new Release(kind,code,version,entry.path("osType").intValue(),url,hash,size,status));
            }
            return new BaselineUpstreamIndex(seq,ScapPackage.digest(payload),expires,List.copyOf(releases));
        }catch(Exception e){throw new IllegalArgumentException("上游索引签名、有效期或内容范围校验失败");}
    }
    private static int port(URI uri){return uri.getPort()==-1?(uri.getScheme().equals("https")?443:80):uri.getPort();}
    private static byte[] decode(String value){byte[] decoded=Base64.getDecoder().decode(value);require(Base64.getEncoder().encodeToString(decoded).equals(value));return decoded;}
    private static JsonNode parse(byte[] bytes)throws Exception{
        String utf8=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();return JSON.readTree(utf8);
    }
    private static void fields(JsonNode node,String... fields){require(node!=null&&node.isObject());Set<String> keys=new HashSet<>();node.fieldNames().forEachRemaining(keys::add);require(keys.equals(Set.of(fields)));}
    private static String text(JsonNode node,String key,int max){JsonNode v=node.path(key);require(v.isTextual()&&!v.asText().isBlank()&&v.asText().length()<=max);return v.asText();}
    private static void require(boolean ok){if(!ok)throw new IllegalArgumentException();}
}
