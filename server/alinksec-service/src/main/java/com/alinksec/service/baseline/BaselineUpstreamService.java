package com.alinksec.service.baseline;

import com.alinksec.service.library.FeedDownload;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import java.io.*;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** A single bounded worker per process, plus a database lease across replicas. */
@Service
public class BaselineUpstreamService {
    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final BaselineUpstreamProperties props;
    private final FeedDownload download;
    private final BaselinePackageService baseline;
    private final ScapPackageService scap;
    private final Map<String,BaselineUpstreamProperties.Source> catalog=new LinkedHashMap<>();
    private final ExecutorService worker=Executors.newSingleThreadExecutor(r->{Thread t=new Thread(r,"baseline-upstream");t.setDaemon(true);return t;});
    private final AtomicBoolean busy=new AtomicBoolean();
    private static final long LEASE_MS=240_000;
    public BaselineUpstreamService(JdbcTemplate jdbc,PlatformTransactionManager manager,BaselineUpstreamProperties props,FeedDownload download,BaselinePackageService baseline,ScapPackageService scap){
        this.jdbc=jdbc;this.tx=new TransactionTemplate(manager);this.props=props;this.download=download;this.baseline=baseline;this.scap=scap;
    }
    @PostConstruct public void initialize(){
        if(props.getSources().size()>16)throw new IllegalArgumentException("最多配置 16 个基线上游");
        Set<String> scopes=new HashSet<>();
        for(var source:props.getSources()){
            source.validate();if(catalog.putIfAbsent(source.getId(),source)!=null)throw new IllegalArgumentException("基线上游编号重复");
            for(String scope:source.getScopes())if(!scopes.add(scope))throw new IllegalArgumentException("不同基线上游不得声明相同包范围");
        }
        tx.executeWithoutResult(status->{
            BaselineUpstreamGuard.lock(jdbc);
            jdbc.update("UPDATE t_baseline_upstream_source SET configured=0 WHERE configured<>0");
            for(var source:catalog.values()){
                jdbc.update("INSERT INTO t_baseline_upstream_source(id,config_hash,enabled,interval_ms) VALUES(?,?,?,?) ON CONFLICT(id) DO NOTHING",source.getId(),source.fingerprint(),source.isEnabled()?1:0,source.getIntervalMs());
                // A trust or URL change requires an explicit enable after operators inspect the new config.
                jdbc.update("UPDATE t_baseline_upstream_source SET enabled=0,revision=revision+1,etag='',modified='',next_poll=0,config_hash=? WHERE id=? AND config_hash<>?",source.fingerprint(),source.getId(),source.fingerprint());
                jdbc.update("UPDATE t_baseline_upstream_source SET configured=1 WHERE id=?",source.getId());
            }
        });
    }
    @PreDestroy public void close(){worker.shutdownNow();}
    public List<Map<String,Object>> list(){
        var rows=jdbc.queryForList("SELECT * FROM t_baseline_upstream_source ORDER BY id");
        for(var row:rows){var source=catalog.get(row.get("id").toString());row.put("name",source==null?row.get("id"):source.getName());row.put("url",source==null?"":source.getUrl());row.put("keySha256",source==null?"":source.keyHash());row.put("scopes",source==null?List.of():source.getScopes());}
        return rows;
    }
    public Map<String,Object> detail(String id){
        var state=one("SELECT * FROM t_baseline_upstream_source WHERE id=?",id);
        state.put("receipt",state.get("receipt_id")==null?null:one("SELECT id,sequence,payload_sha256,key_sha256,expires_at,fetched_at FROM t_baseline_upstream_receipt WHERE id=?",state.get("receipt_id")));
        state.put("releases",jdbc.queryForList("""
                SELECT r.id,r.kind,r.code,r.version,r.os_type,r.sha256,r.size_bytes,r.remote_status,r.state,r.attempts,r.issue,r.package_id,r.imported_at,
                       r.first_receipt,r.current_receipt,r.import_receipt,a.sequence,a.key_sha256,a.payload_sha256,a.expires_at
                FROM t_baseline_upstream_release r JOIN t_baseline_upstream_receipt a ON a.id=r.current_receipt WHERE r.source_id=? ORDER BY a.sequence DESC,r.code,r.version
                """,id));
        state.put("attempts",jdbc.queryForList("SELECT * FROM t_baseline_upstream_attempt WHERE source_id=? ORDER BY started_at DESC,id DESC LIMIT 100",id));
        return state;
    }
    public record Schedule(long revision,boolean enabled,long intervalMs,String note){}
    public Map<String,Object> schedule(String id,Schedule change,Long actor){
        ScapStore.actor(actor);configured(id);if(change==null)throw new IllegalArgumentException("缺少更新计划");BaselineUpstreamProperties.interval(change.intervalMs());ScapStore.note(change.note());
        tx.executeWithoutResult(status->{BaselineUpstreamGuard.lock(jdbc);
            if(jdbc.update("UPDATE t_baseline_upstream_source SET enabled=?,interval_ms=?,revision=revision+1,next_poll=0 WHERE id=? AND revision=?",change.enabled()?1:0,change.intervalMs(),id,change.revision())!=1)throw new IllegalArgumentException("上游计划已变化，请刷新后重试");
            recordControl(id,"schedule",actor,change.note().strip());
        });return detail(id);
    }
    public Map<String,String> trigger(String id,Long actor){ScapStore.actor(actor);configured(id);requireEnabled(state(id));return enqueue(id,"manual",actor);}
    public Map<String,Object> retry(String sourceId,String releaseId,Long actor){
        ScapStore.actor(actor);configured(sourceId);
        tx.executeWithoutResult(status->{BaselineUpstreamGuard.lock(jdbc);requireEnabled(state(sourceId));
            var row=one("SELECT * FROM t_baseline_upstream_release WHERE id=? AND source_id=?",releaseId,sourceId);
            if(!row.get("state").equals("failed")||!row.get("remote_status").equals("active"))throw new IllegalArgumentException("仅活动的失败版本可以重试");
            jdbc.update("UPDATE t_baseline_upstream_release SET state='pending',attempts=0,issue='' WHERE id=?",releaseId);
            jdbc.update("UPDATE t_baseline_upstream_source SET next_poll=0 WHERE id=?",sourceId);recordControl(sourceId,"retry",actor,"管理员重新尝试失败版本 "+releaseId);
        });return detail(sourceId);
    }
    @Scheduled(fixedDelay=60_000,initialDelay=60_000) public void tick(){
        if(busy.get())return;
        var due=jdbc.queryForList("SELECT id FROM t_baseline_upstream_source WHERE enabled=1 AND configured=1 AND next_poll<=? ORDER BY next_poll,id LIMIT 1",System.currentTimeMillis());
        if(!due.isEmpty())try{enqueue(due.get(0).get("id").toString(),"scheduled",0L);}catch(IllegalArgumentException ignored){/* another trigger already owns this worker */}
    }
    private Map<String,String> enqueue(String id,String trigger,long actor){
        if(!busy.compareAndSet(false,true))throw new IllegalArgumentException("已有基线上游更新正在执行，请稍后刷新");
        String attempt=UUID.randomUUID().toString();
        try{
            var expected=tx.execute(status->{BaselineUpstreamGuard.lock(jdbc);var state=state(id);requireEnabled(state);
                jdbc.update("INSERT INTO t_baseline_upstream_attempt(id,source_id,trigger_type,actor,started_at,outcome) VALUES(?,?,?,?,?,'queued')",attempt,id,trigger,actor,System.currentTimeMillis());return state;});
            worker.execute(()->{try{run(id,attempt,number(expected,"revision"));}finally{busy.set(false);}});
        }catch(RuntimeException e){busy.set(false);throw e;}
        return Map.of("attemptId",attempt,"state","queued");
    }
    private record Context(String source,String owner,String attempt,long revision,String config,long deadline){}
    private Context acquire(String id,String attempt,long expectedRevision){
        return tx.execute(status->{
            long now=System.currentTimeMillis();String owner=UUID.randomUUID().toString();
            BaselineUpstreamGuard.lock(jdbc);var state=state(id);
            if(number(state,"enabled")!=1||number(state,"configured")!=1||number(state,"revision")!=expectedRevision){
                jdbc.update("UPDATE t_baseline_upstream_attempt SET outcome='interrupted',issue='source_changed',finished_at=? WHERE id=?",now,attempt);return null;
            }
            if(jdbc.update("UPDATE t_baseline_upstream_gate SET lease_owner=?,lease_until=? WHERE id=1 AND lease_until<=?",owner,now+LEASE_MS,now)!=1){
                jdbc.update("UPDATE t_baseline_upstream_attempt SET outcome='interrupted',issue='worker_busy',finished_at=? WHERE id=?",now,attempt);return null;
            }
            jdbc.update("UPDATE t_baseline_upstream_attempt SET outcome='interrupted',issue='worker_interrupted',finished_at=? WHERE outcome IN ('running','queued') AND started_at<=?",now,now-LEASE_MS);
            jdbc.update("UPDATE t_baseline_upstream_release SET state='failed',issue='worker_interrupted' WHERE state='pending' AND attempts>=3");
            jdbc.update("UPDATE t_baseline_upstream_attempt SET outcome='running',started_at=? WHERE id=?",now,attempt);
            jdbc.update("UPDATE t_baseline_upstream_source SET next_poll=? WHERE id=?",now+number(state,"interval_ms"),id);
            return new Context(id,owner,attempt,number(state,"revision"),state.get("config_hash").toString(),now+180_000);
        });
    }
    private void run(String id,String attempt,long expectedRevision){
        Context context=null;int imported=0;String outcome="success",issue="";
        try{
            context=acquire(id,attempt,expectedRevision);if(context==null)return;
            var source=configured(id);var state=state(id);Map<String,String> headers=new HashMap<>();
            if(validReceipt(state,context.config(),System.currentTimeMillis())){
                if(!state.get("etag").toString().isEmpty())headers.put("If-None-Match",state.get("etag").toString());
                if(!state.get("modified").toString().isEmpty())headers.put("If-Modified-Since",state.get("modified").toString());
            }
            try(var fetched=download.fetchBounded(source.getUrl(),headers,BaselineUpstreamIndex.MAX_ENVELOPE,30_000)){
                if(fetched.status()==304){if(headers.isEmpty()||!validReceipt(state,context.config(),System.currentTimeMillis()))throw new Failure("index_expired");
                    var current=context;
                    tx.executeWithoutResult(status->{assertCurrent(current);if(!validReceipt(state(id),current.config(),System.currentTimeMillis()))throw new Failure("index_expired");});
                }else{
                    byte[] bytes=Files.readAllBytes(fetched.file());BaselineUpstreamIndex index;
                    try{index=BaselineUpstreamIndex.verify(bytes,source,System.currentTimeMillis());}catch(IllegalArgumentException e){throw new Failure("index_invalid");}
                    accept(context,source,index,bytes,fetched.etag(),fetched.modified());
                }
            }
            var pending=jdbc.queryForList("SELECT * FROM t_baseline_upstream_release WHERE source_id=? AND remote_status='active' AND state IN ('pending','failed') AND attempts<3 ORDER BY code,version LIMIT 2",id);
            for(var release:pending){
                if(Thread.currentThread().isInterrupted()||System.currentTimeMillis()>=context.deadline())throw new Failure("worker_interrupted");
                try{importRelease(context,release);imported++;}catch(Failure e){failRelease(context,release,e.code);outcome="partial";issue=e.code;}
            }
        }catch(Failure e){outcome="failed";issue=e.code;}
        catch(Exception e){outcome="failed";issue="sync_failed";}
        finally{if(context!=null)finish(context,outcome,issue,imported);}
    }
    private void assertCurrent(Context context){
        BaselineUpstreamGuard.lock(jdbc);var gate=one("SELECT lease_owner,lease_until FROM t_baseline_upstream_gate WHERE id=1");var source=state(context.source());
        if(!gate.get("lease_owner").equals(context.owner())||number(gate,"lease_until")<=System.currentTimeMillis()||number(source,"revision")!=context.revision()||!source.get("config_hash").equals(context.config())||number(source,"enabled")!=1||number(source,"configured")!=1||Thread.currentThread().isInterrupted()||System.currentTimeMillis()>=context.deadline())throw new Failure("source_changed");
    }
    private boolean validReceipt(Map<String,Object> state,String config,long now){
        if(state.get("receipt_id")==null)return false;
        var receipts=jdbc.queryForList("SELECT expires_at,config_hash FROM t_baseline_upstream_receipt WHERE id=?",state.get("receipt_id"));
        return receipts.size()==1&&receipts.get(0).get("config_hash").equals(config)&&number(receipts.get(0),"expires_at")>now;
    }
    private void accept(Context context,BaselineUpstreamProperties.Source source,BaselineUpstreamIndex index,byte[] envelope,String etag,String modified){
        tx.executeWithoutResult(status->{
            assertCurrent(context);if(index.expiresAt()<=System.currentTimeMillis())throw new Failure("index_expired");var state=state(context.source());long previous=number(state,"sequence");
            if(index.sequence()<previous||(index.sequence()==previous&&!index.payloadHash().equals(state.get("payload_sha256"))))throw new Failure("index_rollback");
            String receipt;
            if(index.sequence()==previous){
                receipt=state.get("receipt_id").toString();var saved=one("SELECT config_hash FROM t_baseline_upstream_receipt WHERE id=?",receipt);
                if(!saved.get("config_hash").equals(context.config()))throw new Failure("index_new_sequence_required");
            }else{
                receipt=UUID.randomUUID().toString();
                jdbc.update("INSERT INTO t_baseline_upstream_receipt(id,source_id,sequence,payload_sha256,key_sha256,config_hash,expires_at,envelope,fetched_at) VALUES(?,?,?,?,?,?,?,?,?)",receipt,context.source(),index.sequence(),index.payloadHash(),source.keyHash(),context.config(),index.expiresAt(),Base64.getEncoder().encodeToString(envelope),System.currentTimeMillis());
            }
            for(var entry:index.releases()){
                var existing=jdbc.queryForList("SELECT * FROM t_baseline_upstream_release WHERE source_id=? AND kind=? AND code=? AND version=?",context.source(),entry.kind(),entry.code(),entry.version());
                if(existing.isEmpty()){
                    if(jdbc.queryForObject("SELECT count(*) FROM t_baseline_upstream_release",Integer.class)>=256)throw new Failure("release_capacity");
                    jdbc.update("INSERT INTO t_baseline_upstream_release(id,source_id,kind,code,version,os_type,url,sha256,size_bytes,remote_status,first_receipt,current_receipt,state) VALUES(?,?,?,?,?,?,?,?,?,?,?,?, 'pending')",UUID.randomUUID().toString(),context.source(),entry.kind(),entry.code(),entry.version(),entry.osType(),entry.url(),entry.sha256(),entry.size(),entry.status(),receipt,receipt);
                }else{
                    var old=existing.get(0);
                    if(!old.get("sha256").equals(entry.sha256())||number(old,"size_bytes")!=entry.size()||number(old,"os_type")!=entry.osType()||!old.get("url").equals(entry.url())||(old.get("remote_status").equals("withdrawn")&&!entry.status().equals("withdrawn")))throw new Failure("release_changed");
                    jdbc.update("UPDATE t_baseline_upstream_release SET remote_status=?,current_receipt=? WHERE id=?",entry.status(),receipt,old.get("id"));
                }
            }
            jdbc.update("UPDATE t_baseline_upstream_source SET sequence=?,payload_sha256=?,receipt_id=?,etag=?,modified=? WHERE id=?",index.sequence(),index.payloadHash(),receipt,validator(etag),validator(modified),context.source());
            // Keep all release evidence plus the newest 20 otherwise unreferenced indexes per source.
            jdbc.update("""
                    DELETE FROM t_baseline_upstream_receipt WHERE source_id=? AND id NOT IN (SELECT first_receipt FROM t_baseline_upstream_release)
                    AND id NOT IN (SELECT current_receipt FROM t_baseline_upstream_release) AND id NOT IN (SELECT import_receipt FROM t_baseline_upstream_release WHERE import_receipt IS NOT NULL) AND id NOT IN (SELECT receipt_id FROM t_baseline_upstream_source WHERE receipt_id IS NOT NULL)
                    AND id NOT IN (SELECT id FROM t_baseline_upstream_receipt WHERE source_id=? ORDER BY sequence DESC LIMIT 20)
                    """,context.source(),context.source());
        });
    }
    private void importRelease(Context context,Map<String,Object> release){
        String id=release.get("id").toString();
        tx.executeWithoutResult(status->{assertCurrent(context);requireRelease(release);jdbc.update("UPDATE t_baseline_upstream_release SET attempts=attempts+1 WHERE id=?",id);});
        byte[] bytes;
        try(var fetched=download.fetchBounded(release.get("url").toString(),Map.of(),number(release,"size_bytes"),30_000)){
            bytes=Files.readAllBytes(fetched.file());if(fetched.status()!=200||bytes.length!=number(release,"size_bytes")||!ScapPackage.digest(bytes).equals(release.get("sha256")))throw new Failure("artifact_digest");
        }catch(Failure e){throw e;}catch(Exception e){throw new Failure("artifact_download");}
        String kind=release.get("kind").toString();ScapPackageService.Prepared prepared=null;
        try{
            var identity=kind.equals("baseline")?BaselinePackageFormat.read(new ByteArrayInputStream(bytes)).document():ScapPackage.read(bytes).manifest();
            if(!identity.path("code").asText().equals(release.get("code"))||!identity.path("version").asText().equals(release.get("version"))||identity.path("osType").asInt()!=number(release,"os_type"))throw new Failure("artifact_identity");
            if(kind.equals("scap"))prepared=scap.prepareUpstream(bytes);
        }catch(Failure e){throw e;}catch(Exception e){throw new Failure("artifact_invalid");}
        var resolved=prepared;
        try{tx.executeWithoutResult(status->{
            assertCurrent(context);requireRelease(release);
            long used=jdbc.queryForObject("SELECT COALESCE(SUM(size_bytes),0) FROM t_baseline_upstream_release WHERE artifact IS NOT NULL",Long.class);
            if(used+bytes.length>props.getMaxArtifactBytes())throw new Failure("artifact_capacity");
            Map<String,Object> pkg;
            try{pkg=kind.equals("baseline")?baseline.importPackage(new ByteArrayInputStream(bytes),0L):scap.saveUpstream(resolved);}catch(IOException e){throw new Failure("artifact_invalid");}
            if(!pkg.get("status").equals("candidate"))throw new Failure("package_already_adopted");
            var bound=jdbc.queryForList("SELECT id FROM t_baseline_upstream_release WHERE kind=? AND package_id=?",kind,pkg.get("id"));
            if(!bound.isEmpty())throw new Failure("package_already_bound");
            jdbc.update("UPDATE t_baseline_upstream_release SET state='imported',issue='',package_id=?,artifact=?,imported_at=?,import_receipt=current_receipt WHERE id=?",pkg.get("id"),Base64.getEncoder().encodeToString(bytes),System.currentTimeMillis(),id);
        });}catch(Failure e){throw e;}catch(Exception e){throw new Failure("artifact_import");}
    }
    private void requireRelease(Map<String,Object> release){
        var fresh=one("SELECT * FROM t_baseline_upstream_release WHERE id=?",release.get("id"));
        var receipt=one("SELECT expires_at,config_hash FROM t_baseline_upstream_receipt WHERE id=?",fresh.get("current_receipt"));
        if(!fresh.get("remote_status").equals("active")||fresh.get("state").equals("imported")||number(receipt,"expires_at")<=System.currentTimeMillis()||!receipt.get("config_hash").equals(state(release.get("source_id").toString()).get("config_hash")))throw new Failure("release_unavailable");
    }
    private void failRelease(Context context,Map<String,Object> release,String issue){tx.executeWithoutResult(status->{assertCurrent(context);jdbc.update("UPDATE t_baseline_upstream_release SET state='failed',issue=? WHERE id=? AND state<>'imported'",issue,release.get("id"));});}
    private void finish(Context context,String outcome,String issue,int imported){
        tx.executeWithoutResult(status->{
            BaselineUpstreamGuard.lock(jdbc);var gate=one("SELECT lease_owner FROM t_baseline_upstream_gate WHERE id=1");
            if(!gate.get("lease_owner").equals(context.owner()))return;
            long now=System.currentTimeMillis();
            jdbc.update("UPDATE t_baseline_upstream_attempt SET outcome=?,issue=?,imported=?,finished_at=? WHERE id=? AND outcome='running'",outcome,issue,imported,now,context.attempt());
            long remaining=jdbc.queryForObject("SELECT count(*) FROM t_baseline_upstream_release WHERE source_id=? AND remote_status='active' AND state IN ('pending','failed') AND attempts<3",Long.class,context.source());
            jdbc.update("UPDATE t_baseline_upstream_source SET last_checked=?,last_outcome=?,next_poll=CASE WHEN ? > 0 THEN ? ELSE next_poll END WHERE id=?",now,issue.isEmpty()?outcome:issue,remaining,now+60_000,context.source());
            jdbc.update("UPDATE t_baseline_upstream_gate SET lease_owner='',lease_until=0 WHERE id=1");pruneAttempts(context.source());
        });
    }
    public byte[] receipt(String source,String id){return Base64.getDecoder().decode(one("SELECT envelope FROM t_baseline_upstream_receipt WHERE id=? AND source_id=?",id,source).get("envelope").toString());}
    public byte[] artifact(String source,String id){var row=one("SELECT artifact,sha256 FROM t_baseline_upstream_release WHERE id=? AND source_id=?",id,source);if(row.get("artifact")==null)throw new IllegalArgumentException("该版本尚未保存下载原件");byte[] bytes=Base64.getDecoder().decode(row.get("artifact").toString());if(!ScapPackage.digest(bytes).equals(row.get("sha256")))throw new IllegalArgumentException("上游原件摘要不匹配");return bytes;}
    private void recordControl(String id,String action,long actor,String note){long now=System.currentTimeMillis();jdbc.update("INSERT INTO t_baseline_upstream_attempt(id,source_id,trigger_type,actor,started_at,finished_at,outcome,note) VALUES(?,?,?,?,?,?,'success',?)",UUID.randomUUID().toString(),id,action,actor,now,now,note);pruneAttempts(id);}
    private void pruneAttempts(String id){jdbc.update("DELETE FROM t_baseline_upstream_attempt WHERE source_id=? AND outcome<>'running' AND id NOT IN (SELECT id FROM t_baseline_upstream_attempt WHERE source_id=? ORDER BY started_at DESC,id DESC LIMIT 100)",id,id);}
    private BaselineUpstreamProperties.Source configured(String id){var source=catalog.get(id);if(source==null)throw new IllegalArgumentException("上游未在服务器配置中启用");return source;}
    private Map<String,Object> state(String id){return one("SELECT * FROM t_baseline_upstream_source WHERE id=?",id);}
    private Map<String,Object> one(String sql,Object... args){var rows=jdbc.queryForList(sql,args);if(rows.size()!=1)throw new IllegalArgumentException("基线上游记录不存在");return rows.get(0);}
    private static long number(Map<String,Object> row,String key){return ((Number)row.get(key)).longValue();}
    private static void requireEnabled(Map<String,Object> state){if(number(state,"enabled")!=1||number(state,"configured")!=1)throw new IllegalArgumentException("请先启用已配置的上游");}
    private static String validator(String value){return value==null||value.chars().anyMatch(c->c<32||c==127)?"":value;}
    private static final class Failure extends RuntimeException{final String code;Failure(String code){super(code);this.code=code;}}
}
