package com.alinksec.service.library;

import com.alinksec.common.util.JsonUtils;
import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.databind.*;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.*;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import java.util.regex.Pattern;

/** A complete, authenticated, bounded visible collection; never a recent-update delta. */
public final class OpenCtiAdapter {
    private OpenCtiAdapter() {}
    public static final String QUERY="""
            query AlinksecIndicators($after: ID, $first: Int!) {
              me { id }
              about { version }
              indicators(first: $first, after: $after, orderBy: created_at, orderMode: asc) {
                pageInfo { hasNextPage endCursor globalCount }
                edges { cursor node {
                  id standard_id name created_at modified pattern_type pattern_version pattern
                  revoked confidence valid_from valid_until x_opencti_detection objectLabel { value }
                } }
              }
            }
            """;
    public static final int PAGE_SIZE=200, MAX_NODE_BYTES=16*1024;
    public static final long MAX_PAGE_BYTES=4L<<20;
    private static final Pattern UUID=Pattern.compile("[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}");
    private static final Pattern HASH=Pattern.compile("\\[\\s*file:hashes\\.'SHA-256'\\s*=\\s*'([a-fA-F0-9]{64})'\\s*\\]");
    private static final ObjectMapper JSON=new ObjectMapper(JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(24).maxStringLength(8192).maxNumberLength(32).build()).build());
    public enum Problem {
        CONFIG("请在部署配置中设置 OpenCTI GraphQL HTTPS 地址、只读密钥、明确审核标签和置信度阈值"),
        RESPONSE("OpenCTI 响应、身份或分页不完整，已有库保留"),
        ACCESS("OpenCTI 访问、认证或响应下载失败，已有库保留"),
        LIMIT("OpenCTI 完整快照超过容量或时间边界，已有库保留"),
        SCOPE("OpenCTI 身份或审核范围已改变，请使用新的来源标识"),
        STALE("另一轮同步已更新 OpenCTI 来源，本轮旧快照未发布");
        private final String message;
        Problem(String message){this.message=message;}
    }
    /** Fixed messages only: transport/parser exception text and GraphQL errors can contain secrets. */
    public static final class Failure extends IllegalArgumentException {
        private final Problem problem;
        private Failure(Problem problem){super(problem.message);this.problem=problem;}
        public Problem problem(){return problem;}
    }
    static Failure failure(Problem problem){return new Failure(problem);}
    public record Config(String url,String key,String tag,int minimumConfidence,int severity,String fingerprint) {}
    public record Indicator(String id,String raw,String digest,int bytes,String hash,String permanentReason,Instant from,Instant until) {
        public String reasonAt(Instant now){
            if(!permanentReason.isEmpty())return permanentReason;
            if(from.isAfter(now))return "future";
            if(until!=null&&!until.isAfter(now))return "expired";
            return "included";
        }
        public long expiresAt(){
            if(until==null)return -1;
            long millis=until.toEpochMilli();
            return until.getNano()%1_000_000==0?millis:Math.addExact(millis,1);
        }
    }
    public record Snapshot(Config config,String principal,String serverVersion,List<Indicator> indicators,
                           int pages,List<String> pageDigests,String digest) {}

    public static String configurationIssue(LibraryProperties.Source source){
        try{config(source,true);return "";}catch(RuntimeException e){return Problem.CONFIG.message;}
    }
    public static String fingerprint(LibraryProperties.Source source){return config(source,false).fingerprint();}
    private static Config config(LibraryProperties.Source source,boolean authentication){
        try{
            if(!"opencti".equals(source.getType()))throw failure(Problem.CONFIG);
            var uri=FeedDownload.validateAddress(source.getUrl());String path=uri.getRawPath();
            if(uri.getRawQuery()!=null||path==null||!path.endsWith("/graphql")||path.contains("%")
                    ||Arrays.asList(path.split("/",-1)).contains("..")||Arrays.asList(path.split("/",-1)).contains("."))throw failure(Problem.CONFIG);
            String key=source.getApiKey(),tag=source.getOpenctiTag();
            if(key==null||authentication&&key.isEmpty()||!key.isEmpty()&&!key.matches("[A-Za-z0-9._~+/=-]{1,4096}")
                    ||tag==null||!tag.matches("[A-Za-z0-9][A-Za-z0-9:._=-]{0,127}")
                    ||source.getOpenctiMinConfidence()<0||source.getOpenctiMinConfidence()>100
                    ||source.getOpenctiSeverity()<1||source.getOpenctiSeverity()>5)throw failure(Problem.CONFIG);
            String fingerprint=digest(JsonUtils.write(new TreeMap<>(Map.of("type","opencti","url",uri.toASCIIString(),"tag",tag,
                    "minimumConfidence",source.getOpenctiMinConfidence(),"severity",source.getOpenctiSeverity()))).getBytes(StandardCharsets.UTF_8));
            return new Config(uri.toASCIIString(),key,tag,source.getOpenctiMinConfidence(),source.getOpenctiSeverity(),fingerprint);
        }catch(Failure e){throw e;}catch(RuntimeException e){throw failure(Problem.CONFIG);}
    }
    public static Snapshot fetch(LibraryProperties.Source source,FeedDownload download,OpenCtiProperties limits)throws IOException {
        limits.validate();Config config=config(source,true);
        long deadline=System.nanoTime()+limits.getRoundTimeoutMs()*1_000_000L,received=0;
        List<Indicator> records=new ArrayList<>();List<String> digests=new ArrayList<>();
        Set<String> ids=new HashSet<>(),cursors=new HashSet<>();String after=null,principal=null,version=null;int total=-1,pages=0;
        boolean more;
        do{
            long remaining=(deadline-System.nanoTime())/1_000_000;
            if(remaining<100||++pages>limits.getMaxPages())throw failure(Problem.LIMIT);
            var variables=new LinkedHashMap<String,Object>();variables.put("after",after);variables.put("first",PAGE_SIZE);
            String request=JsonUtils.write(Map.of("operationName","AlinksecIndicators","query",QUERY,"variables",variables));
            byte[] body;
            try(var response=download.postJsonBounded(config.url(),Map.of("Authorization","Bearer "+config.key(),"Accept","application/json"),
                    request,MAX_PAGE_BYTES,(int)Math.min(remaining,limits.getRequestTimeoutMs()))){
                if(response.status()!=200)throw failure(Problem.RESPONSE);
                body=Files.readAllBytes(response.file());
            }catch(Failure e){throw e;}catch(IOException e){throw failure(Problem.ACCESS);}
            received+=body.length;
            if(received>limits.getMaxSnapshotBytes()||System.nanoTime()>deadline)throw failure(Problem.LIMIT);
            digests.add(digest(body));JsonNode root=parse(body);
            if(root.has("errors")&&!root.path("errors").isNull()
                    &&(!root.path("errors").isArray()||!root.path("errors").isEmpty()))throw failure(Problem.RESPONSE);
            JsonNode data=object(root,"data"),me=object(data,"me"),about=object(data,"about");
            String identity=identifier(me,"id"),server=text(about,"version",64,false);
            if(!server.matches("[0-9][A-Za-z0-9.+_-]{0,63}"))throw failure(Problem.RESPONSE);
            if(principal!=null&&(!principal.equals(identity)||!version.equals(server)))throw failure(Problem.RESPONSE);
            principal=identity;version=server;
            JsonNode connection=object(data,"indicators"),info=object(connection,"pageInfo"),edges=connection.path("edges");
            int declared=integer(info,"globalCount",0,limits.getMaxIndicators());
            if(total!=-1&&total!=declared)throw failure(Problem.RESPONSE);total=declared;
            if(!info.path("hasNextPage").isBoolean()||!edges.isArray()||edges.size()>PAGE_SIZE)throw failure(Problem.RESPONSE);
            more=info.path("hasNextPage").booleanValue();String end=text(info,"endCursor",2048,true),last="";
            if(edges.isEmpty()&&(more||pages>1||total!=0))throw failure(Problem.RESPONSE);
            for(JsonNode edge:edges){
                last=text(edge,"cursor",2048,false);
                if(!cursors.add(last))throw failure(Problem.RESPONSE);
                Indicator record=indicator(object(edge,"node"),config);
                if(!ids.add(record.id()))throw failure(Problem.RESPONSE);
                records.add(record);
                if(records.size()>limits.getMaxIndicators()||records.size()>total)throw failure(Problem.LIMIT);
            }
            if(!edges.isEmpty()&&!last.equals(end)||more&&(end.isEmpty()||end.equals(after)))throw failure(Problem.RESPONSE);
            after=end;
        }while(more);
        if(records.size()!=total)throw failure(Problem.RESPONSE);
        var canonical=new StringBuilder();records.stream().sorted(Comparator.comparing(Indicator::id))
                .forEach(r->canonical.append(r.id()).append(':').append(r.digest()).append('\n'));
        return new Snapshot(config,principal,version,List.copyOf(records),pages,List.copyOf(digests),digest(canonical.toString().getBytes(StandardCharsets.UTF_8)));
    }
    static JsonNode parse(byte[] bytes){
        try{
            String value=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
            try(var parser=JSON.createParser(value)){
                JsonNode root=JSON.readTree(parser);
                if(root==null||!root.isObject()||parser.nextToken()!=null)throw failure(Problem.RESPONSE);
                return root;
            }
        }catch(Failure e){throw e;}catch(Exception e){throw failure(Problem.RESPONSE);}
    }
    static Indicator indicator(JsonNode node,Config config){
        for(String field:List.of("id","standard_id","name","created_at","modified","pattern_type","pattern_version","pattern",
                "revoked","confidence","valid_from","valid_until","x_opencti_detection","objectLabel"))
            if(!node.has(field))throw failure(Problem.RESPONSE);
        String id=identifier(node,"id"),standard=text(node,"standard_id",64,false);
        if(!standard.startsWith("indicator--")||!UUID.matcher(standard.substring(11)).matches())throw failure(Problem.RESPONSE);
        text(node,"name",512,false);date(node,"created_at",false);date(node,"modified",true);
        if(!node.path("revoked").isBoolean()||!node.path("x_opencti_detection").isNull()&&!node.path("x_opencti_detection").isBoolean())throw failure(Problem.RESPONSE);
        Integer confidence=node.path("confidence").isNull()?null:integer(node,"confidence",0,100);
        String pattern=nullableText(node,"pattern",4096),type=nullableText(node,"pattern_type",64),patternVersion=nullableText(node,"pattern_version",32);
        Instant from=date(node,"valid_from",true),until=date(node,"valid_until",true);
        if(from!=null&&until!=null&&until.isBefore(from))throw failure(Problem.RESPONSE);
        boolean approved=false;JsonNode labels=node.path("objectLabel");
        if(!labels.isNull()){
            if(!labels.isArray()||labels.size()>64)throw failure(Problem.RESPONSE);
            for(JsonNode label:labels)if(config.tag().equals(text(label,"value",128,false)))approved=true;
        }
        var match=HASH.matcher(pattern==null?"":pattern);String hash=match.matches()?match.group(1).toLowerCase(Locale.ROOT):"";
        String reason=node.path("revoked").booleanValue()?"revoked":!approved?"not_approved":!node.path("x_opencti_detection").asBoolean(false)?"detection_disabled"
                :confidence==null||confidence<config.minimumConfidence()?"confidence":!Set.of("2.0","2.1").contains(patternVersion==null?"":patternVersion)?"unsupported_version"
                :!"stix".equals(type)||hash.isEmpty()?"unsupported_pattern":from==null?"missing_validity":"";
        String raw=JsonUtils.write(node);byte[] bytes=raw.getBytes(StandardCharsets.UTF_8);
        if(bytes.length>MAX_NODE_BYTES)throw failure(Problem.LIMIT);
        return new Indicator(id,raw,digest(bytes),bytes.length,hash,reason,from,until);
    }
    private static JsonNode object(JsonNode node,String field){JsonNode v=node.path(field);if(!v.isObject())throw failure(Problem.RESPONSE);return v;}
    private static String identifier(JsonNode node,String field){String v=text(node,field,36,false);if(!UUID.matcher(v).matches())throw failure(Problem.RESPONSE);return v;}
    private static String nullableText(JsonNode node,String field,int max){return node.path(field).isNull()?null:text(node,field,max,true);}
    private static String text(JsonNode node,String field,int max,boolean empty){
        JsonNode v=node.path(field);
        if(!v.isTextual()||v.textValue().length()>max||!empty&&v.textValue().isEmpty()||v.textValue().indexOf('\0')>=0)throw failure(Problem.RESPONSE);
        return v.textValue();
    }
    private static int integer(JsonNode node,String field,int min,int max){JsonNode v=node.path(field);if(!v.isIntegralNumber()||!v.canConvertToInt()||v.intValue()<min||v.intValue()>max)throw failure(Problem.RESPONSE);return v.intValue();}
    private static Instant date(JsonNode node,String field,boolean nullable){
        if(nullable&&node.path(field).isNull())return null;
        try{var date=OffsetDateTime.parse(text(node,field,64,false));if(date.getYear()<1||date.getYear()>9999)throw failure(Problem.RESPONSE);return date.toInstant();}
        catch(Failure e){throw e;}catch(RuntimeException e){throw failure(Problem.RESPONSE);}
    }
    public static String digest(byte[] bytes){
        try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
        catch(java.security.NoSuchAlgorithmException e){throw new IllegalStateException(e);}
    }
}
