package com.alinksec.service.library;

import com.alinksec.common.util.JsonUtils;
import org.springframework.jdbc.core.JdbcTemplate;
import java.io.*;
import java.time.Instant;
import java.time.Clock;
import java.util.*;

/** Current upstream fields, local lifecycle decisions and the effective source commit together. */
public final class OpenCtiService {
    private final LibraryCatalog catalog;
    private final FeedDownload download;
    private final JdbcTemplate jdbc;
    private final OpenCtiProperties limits;
    private final Clock clock;
    public OpenCtiService(LibraryCatalog catalog,FeedDownload download,JdbcTemplate jdbc,OpenCtiProperties limits){
        this(catalog,download,jdbc,limits,Clock.systemUTC());
    }
    public OpenCtiService(LibraryCatalog catalog,FeedDownload download,JdbcTemplate jdbc,OpenCtiProperties limits,Clock clock){
        this.catalog=catalog;this.download=download;this.jdbc=jdbc;this.limits=limits;this.clock=clock;limits.validate();
    }
    private Map<String,Object> stored(String id){
        var rows=jdbc.queryForList("SELECT * FROM t_opencti_source WHERE source_id=?",id);
        return rows.isEmpty()?Map.of():rows.get(0);
    }
    public String configurationIssue(LibraryProperties.Source source){
        var old=stored(source.getId());
        if(old.isEmpty())return "";
        try{
            if(!"opencti".equals(source.getType())||!old.get("configuration_sha256").equals(OpenCtiAdapter.fingerprint(source)))
                return OpenCtiAdapter.failure(OpenCtiAdapter.Problem.SCOPE).getMessage();
            return "";
        }catch(RuntimeException e){return OpenCtiAdapter.failure(OpenCtiAdapter.Problem.SCOPE).getMessage();}
    }
    public Map<String,Object> sync(LibraryProperties.Source source)throws IOException {
        String id=source.getId();var before=stored(id);
        if(!configurationIssue(source).isEmpty())throw OpenCtiAdapter.failure(OpenCtiAdapter.Problem.SCOPE);
        var snapshot=OpenCtiAdapter.fetch(source,download,limits);
        try{return catalog.nativeTransaction(id,()->{
            var current=stored(id);
            if(!source.getId().equals(id)||!snapshot.config().fingerprint().equals(OpenCtiAdapter.fingerprint(source)))
                throw OpenCtiAdapter.failure(OpenCtiAdapter.Problem.SCOPE);
            if(!sameRevision(before,current))throw OpenCtiAdapter.failure(OpenCtiAdapter.Problem.STALE);
            if(!current.isEmpty()&&(!current.get("configuration_sha256").equals(snapshot.config().fingerprint())
                    ||!current.get("principal_id").equals(snapshot.principal())))throw OpenCtiAdapter.failure(OpenCtiAdapter.Problem.SCOPE);
            if(current.isEmpty()&&(jdbc.queryForObject("SELECT count(*) FROM t_security_hash WHERE source_id=?",Long.class,id)>0
                    ||jdbc.queryForObject("SELECT count(*) FROM t_security_rule WHERE source_id=?",Long.class,id)>0
                    ||jdbc.queryForObject("SELECT count(*) FROM t_security_cve WHERE source_id=?",Long.class,id)>0))
                throw OpenCtiAdapter.failure(OpenCtiAdapter.Problem.SCOPE);
            long bytes=snapshot.indicators().stream().mapToLong(OpenCtiAdapter.Indicator::bytes).sum();
            var storage=jdbc.queryForMap("SELECT COALESCE(sum(document_bytes),0) AS bytes,count(*) AS total FROM t_opencti_indicator WHERE source_id<>?",id);
            if(bytes>limits.getMaxSnapshotBytes()||bytes+((Number)storage.get("bytes")).longValue()>128L<<20
                    ||snapshot.indicators().size()+((Number)storage.get("total")).longValue()>100_000
                    ||current.isEmpty()&&jdbc.queryForObject("SELECT count(*) FROM t_opencti_source",Long.class)>=64)
                throw OpenCtiAdapter.failure(OpenCtiAdapter.Problem.LIMIT);
            Instant now=clock.instant();Map<String,SignaturePackage.Hash> hashes=new TreeMap<>();Map<String,Integer> reasons=new TreeMap<>();
            for(var item:snapshot.indicators()){
                String reason=item.reasonAt(now);reasons.merge(reason,1,Integer::sum);
                if(reason.equals("included"))hashes.put(item.hash(),SignaturePackage.checkedHash(item.hash(),"OpenCTI.KnownHash",snapshot.config().severity()));
            }
            var policy=Map.of("tag",snapshot.config().tag(),"minimumConfidence",snapshot.config().minimumConfidence(),"severity",snapshot.config().severity());
            long revision=current.isEmpty()?1:((Number)current.get("revision")).longValue()+1;
            jdbc.update("""
                    INSERT INTO t_opencti_source(source_id,configuration_sha256,principal_id,revision,server_version,snapshot_sha256,
                        snapshot_at,evaluated_at,visible_count,hash_count,page_count,policy,statistics)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(source_id) DO UPDATE SET revision=EXCLUDED.revision,
                        server_version=EXCLUDED.server_version,snapshot_sha256=EXCLUDED.snapshot_sha256,snapshot_at=EXCLUDED.snapshot_at,
                        evaluated_at=EXCLUDED.evaluated_at,visible_count=EXCLUDED.visible_count,hash_count=EXCLUDED.hash_count,
                        page_count=EXCLUDED.page_count,policy=EXCLUDED.policy,statistics=EXCLUDED.statistics,expiry_error=''
                    """,id,snapshot.config().fingerprint(),snapshot.principal(),revision,snapshot.serverVersion(),snapshot.digest(),
                    now.toString(),now.toString(),snapshot.indicators().size(),hashes.size(),snapshot.pages(),JsonUtils.write(policy),JsonUtils.write(reasons));
            jdbc.update("DELETE FROM t_opencti_indicator WHERE source_id=?",id);
            jdbc.batchUpdate("""
                    INSERT INTO t_opencti_indicator(source_id,indicator_id,document,document_sha256,document_bytes,sha256,included,reason,expires_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,snapshot.indicators(),200,(stmt,item)->{
                String reason=item.reasonAt(now);stmt.setString(1,id);stmt.setString(2,item.id());stmt.setString(3,item.raw());stmt.setString(4,item.digest());
                stmt.setInt(5,item.bytes());stmt.setString(6,item.hash());stmt.setInt(7,reason.equals("included")?1:0);stmt.setString(8,reason);stmt.setLong(9,item.expiresAt());
            });
            try{
                var release=catalog.nativeSignatures(id,new SignaturePackage("",hashes,List.of()));
                var audit=new LinkedHashMap<String,Object>();audit.put("source_id",id);audit.put("snapshot_sha256",snapshot.digest());
                audit.put("server_version",snapshot.serverVersion());audit.put("policy",policy);audit.put("pages",snapshot.pages());
                audit.put("page_sha256",snapshot.pageDigests());audit.put("visible_indicators",snapshot.indicators().size());
                audit.put("hashes",hashes.size());audit.put("decisions",reasons);audit.put("evaluated_at",now.toString());audit.put("db_version",release.get("dbVersion"));
                catalog.nativeIndicatorEvent(id,"opencti_snapshot",audit);
                return result(id,hashes.size(),release);
            }catch(IOException e){throw new UncheckedIOException(e);}
        });}catch(UncheckedIOException e){throw e.getCause();}
    }
    private static boolean sameRevision(Map<String,Object> before,Map<String,Object> current){
        return before.isEmpty()?current.isEmpty():!current.isEmpty()
                &&((Number)before.get("revision")).longValue()==((Number)current.get("revision")).longValue();
    }
    private static Map<String,Object> result(String id,int count,Map<String,Object> release){
        var result=new LinkedHashMap<String,Object>(release);result.put("sourceId",id);result.put("entryCount",count);return result;
    }
    public boolean hasExpired(){
        return jdbc.queryForObject("""
                SELECT count(*) FROM t_opencti_indicator i JOIN t_security_source_lifecycle l ON l.source_id=i.source_id
                WHERE i.included=1 AND i.expires_at>=0 AND i.expires_at<=? AND l.retired=0
                """,Long.class,clock.instant().toEpochMilli())>0;
    }
    /** Local expiry also runs for paused/removed configurations, using the previously committed policy. */
    public Map<String,Object> expireNext()throws IOException {
        var ids=jdbc.queryForList("""
                SELECT i.source_id FROM t_opencti_indicator i JOIN t_security_source_lifecycle l ON l.source_id=i.source_id
                WHERE i.included=1 AND i.expires_at>=0 AND i.expires_at<=? AND l.retired=0
                ORDER BY i.expires_at,i.source_id LIMIT 1
                """,String.class,clock.instant().toEpochMilli());
        if(ids.isEmpty())return Map.of();String id=ids.get(0);
        try{return catalog.nativeTransaction(id,()->{
            var old=stored(id);Instant now=clock.instant();
            int changed=jdbc.update("UPDATE t_opencti_indicator SET included=0,reason='expired' WHERE source_id=? AND included=1 AND expires_at>=0 AND expires_at<=?",id,now.toEpochMilli());
            if(changed==0)return Map.<String,Object>of();
            int severity=JsonUtils.read(old.get("policy").toString()).path("severity").intValue();
            Map<String,SignaturePackage.Hash> hashes=new TreeMap<>();
            for(String hash:jdbc.queryForList("SELECT DISTINCT sha256 FROM t_opencti_indicator WHERE source_id=? AND included=1 ORDER BY sha256",String.class,id))
                hashes.put(hash,SignaturePackage.checkedHash(hash,"OpenCTI.KnownHash",severity));
            Map<String,Integer> reasons=new TreeMap<>();
            for(var row:jdbc.queryForList("SELECT reason,count(*) AS total FROM t_opencti_indicator WHERE source_id=? GROUP BY reason",id))
                reasons.put(row.get("reason").toString(),((Number)row.get("total")).intValue());
            jdbc.update("UPDATE t_opencti_source SET revision=revision+1,evaluated_at=?,hash_count=?,statistics=?,expiry_error='' WHERE source_id=?",now.toString(),hashes.size(),JsonUtils.write(reasons),id);
            jdbc.update("UPDATE t_security_feed_state SET entry_count=? WHERE source_id=?",hashes.size(),id);
            try{
                var release=catalog.nativeSignatures(id,new SignaturePackage("",hashes,List.of()));
                catalog.nativeIndicatorEvent(id,"opencti_expiry",Map.of("source_id",id,"snapshot_sha256",old.get("snapshot_sha256"),
                        "expired_indicators",changed,"hashes",hashes.size(),"evaluated_at",now.toString(),"db_version",release.get("dbVersion")));
                return result(id,hashes.size(),release);
            }catch(IOException e){throw new UncheckedIOException(e);}
        });}catch(RuntimeException e){
            jdbc.update("UPDATE t_opencti_source SET expiry_error='已知指标到期撤出未能发布，将继续重试；请检查发布存储' WHERE source_id=?",id);
            if(e instanceof UncheckedIOException io)throw io.getCause();throw e;
        }
    }
    public void deliveryDeferred(String id,boolean deferred){jdbc.update("UPDATE t_opencti_source SET delivery_deferred=? WHERE source_id=?",deferred?1:0,id);}
    public Map<String,Object> state(String id){
        var rows=jdbc.queryForList("""
                SELECT server_version,snapshot_sha256,snapshot_at,evaluated_at,visible_count,hash_count,page_count,policy,
                    statistics,expiry_error,delivery_deferred FROM t_opencti_source WHERE source_id=?
                """,id);
        if(rows.isEmpty())return Map.of("identityBound",false,"maxIndicators",limits.getMaxIndicators(),"maxPages",limits.getMaxPages());
        var row=new LinkedHashMap<String,Object>(rows.get(0));row.put("identityBound",true);
        row.put("policy",JsonUtils.read(row.get("policy").toString()));row.put("statistics",JsonUtils.read(row.get("statistics").toString()));
        boolean retired=catalog.isRetired(id);row.put("retired",retired);row.put("effective_hashes",retired?0:row.get("hash_count"));
        row.put("expiry_pending",!retired&&jdbc.queryForObject("SELECT count(*) FROM t_opencti_indicator WHERE source_id=? AND included=1 AND expires_at>=0 AND expires_at<=?",Long.class,id,clock.instant().toEpochMilli())>0);
        return row;
    }
    public Map<String,Object> indicators(String id,int page,int size){
        if(page<1||page>100_000||size<1||size>100)throw new IllegalArgumentException("指标分页参数无效");
        var rows=jdbc.queryForList("""
                SELECT indicator_id,document,document_sha256,sha256,included,reason FROM t_opencti_indicator
                WHERE source_id=? ORDER BY indicator_id LIMIT ? OFFSET ?
                """,id,size,(page-1)*size);
        var entries=new ArrayList<Map<String,Object>>();boolean retired=catalog.isRetired(id);
        for(var row:rows){
            var entry=new LinkedHashMap<String,Object>(row);var doc=verifiedDocument(entry);
            for(String field:List.of("name","confidence","valid_from","valid_until","revoked","x_opencti_detection","objectLabel"))entry.put(field,doc.path(field));
            entry.put("effective",!retired&&((Number)entry.get("included")).intValue()==1);entries.add(entry);
        }
        return Map.of("sourceId",id,"state",state(id),"items",entries,"total",jdbc.queryForObject("SELECT count(*) FROM t_opencti_indicator WHERE source_id=?",Long.class,id),"page",page,"size",size);
    }
    public Map<String,Object> detail(String id,String indicatorId){
        if(!indicatorId.matches("[a-f0-9-]{36}"))throw new IllegalArgumentException("指标标识无效");
        var rows=jdbc.queryForList("SELECT indicator_id,document,document_sha256,sha256,included,reason FROM t_opencti_indicator WHERE source_id=? AND indicator_id=?",id,indicatorId);
        if(rows.isEmpty())throw new IllegalArgumentException("当前快照中不存在该指标");
        var row=new LinkedHashMap<String,Object>(rows.get(0));row.put("document",verifiedDocument(row));
        row.put("effective",!catalog.isRetired(id)&&((Number)row.get("included")).intValue()==1);row.put("sourceId",id);row.put("state",state(id));return row;
    }
    private static com.fasterxml.jackson.databind.JsonNode verifiedDocument(Map<String,Object> row){
        String document=row.remove("document").toString();
        if(!OpenCtiAdapter.digest(document.getBytes(java.nio.charset.StandardCharsets.UTF_8)).equals(row.get("document_sha256")))
            throw new IllegalStateException("保留的 OpenCTI 指标字段摘要不一致，请检查持久化存储");
        return JsonUtils.read(document);
    }
}
