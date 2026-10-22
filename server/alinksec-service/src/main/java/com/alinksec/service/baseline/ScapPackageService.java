package com.alinksec.service.baseline;

import com.alinksec.common.util.JsonUtils;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class ScapPackageService {
    private final JdbcTemplate jdbc;
    private final ScapTaskService tasks;
    private final ScapResolver resolver;
    private final org.springframework.transaction.support.TransactionTemplate transaction;
    public ScapPackageService(JdbcTemplate jdbc,ScapTaskService tasks,ScapResolver resolver,org.springframework.transaction.PlatformTransactionManager manager) {
        this.jdbc=jdbc;this.tasks=tasks;this.resolver=resolver;this.transaction=new org.springframework.transaction.support.TransactionTemplate(manager);
    }
    public record Decision(Integer revision,String action,String note,List<String> agentIds) {}

    public List<Map<String,Object>> list() {
        return jdbc.queryForList("SELECT id,code,version,name,os_type,os_version_pattern,status,revision,source_sha256,content_sha256,created_by,created_at FROM t_scap_package ORDER BY created_at DESC,id DESC LIMIT 1000");
    }
    public Map<String,Object> detail(String id) {
        var row=ScapStore.one(jdbc,"SELECT * FROM t_scap_package WHERE id=?",id);
        ScapStore.packageContent(row);row.remove("content_zip");row.remove("source_zip");row.put("metadata",JsonUtils.read(row.get("metadata").toString()));row.put("resolution",JsonUtils.read(row.get("resolution").toString()));
        row.put("upstream",BaselineUpstreamGuard.provenance(jdbc,"scap",id));
        row.put("reviews",jdbc.queryForList("SELECT revision,action,note,actor,created_at FROM t_scap_package_review WHERE package_id=? ORDER BY revision",id));
        String task=row.get("last_test_task")==null?null:row.get("last_test_task").toString();
        row.put("testReady",ScapTaskService.testReady(jdbc,task));
        if (task!=null) row.put("testTask",tasks.detail(task));
        return row;
    }
    public byte[] content(String id) {
        return ScapStore.packageContent(ScapStore.one(jdbc,"SELECT * FROM t_scap_package WHERE id=?",id)).archive();
    }
    public byte[] source(String id) {
        var row=ScapStore.one(jdbc,"SELECT * FROM t_scap_package WHERE id=?",id);ScapStore.packageContent(row);
        return Base64.getDecoder().decode(row.get("source_zip").toString());
    }
    public Map<String,Object> importContent(byte[] bytes,Long actor) {
        ScapStore.actor(actor);
        var source=ScapPackage.read(bytes);var m=source.manifest();String code=m.path("code").asText(),version=m.path("version").asText();
        // Native parsing happens before opening a write transaction. In
        // particular, a SQLite import must not block heartbeats for 15 seconds.
        var found=jdbc.queryForList("SELECT * FROM t_scap_package WHERE code=? AND version=?",code,version);
        if (!found.isEmpty()) return sameSource(found.get(0),source);
        var resolved=resolver.resolve(source);var content=resolved.content();
        if (!content.manifest().equals(source.manifest())) throw new IllegalArgumentException("标准解析不得更改内容身份");
        return transaction.execute(status->saveResolved(bytes,source,resolved,actor));
    }
    record Prepared(byte[] bytes,ScapPackage source,ScapResolver.Resolved resolved) {}
    Prepared prepareUpstream(byte[] bytes) {
        var source=ScapPackage.read(bytes);
        var found=jdbc.queryForList("SELECT * FROM t_scap_package WHERE code=? AND version=?",source.manifest().path("code").asText(),source.manifest().path("version").asText());
        if(!found.isEmpty()){sameSource(found.get(0),source);return new Prepared(bytes,source,null);}
        var resolved=resolver.resolve(source);
        if(!resolved.content().manifest().equals(source.manifest()))throw new IllegalArgumentException("标准解析不得更改内容身份");
        return new Prepared(bytes,source,resolved);
    }
    Map<String,Object> saveUpstream(Prepared prepared) {
        // Actor 0 denotes the scheduled system importer, never a human reviewer.
        if(prepared.resolved()!=null)return saveResolved(prepared.bytes(),prepared.source(),prepared.resolved(),0L);
        var m=prepared.source().manifest();return sameSource(ScapStore.one(jdbc,"SELECT * FROM t_scap_package WHERE code=? AND version=?",m.path("code").asText(),m.path("version").asText()),prepared.source());
    }
    Map<String,Object> sameSource(Map<String,Object> existing,ScapPackage source) {
        ScapStore.packageContent(existing);
        if (JsonUtils.read(existing.get("resolution").toString()).path("sourceCanonicalSha256").asText().equals(source.sha256())) return detail(existing.get("id").toString());
        throw new IllegalArgumentException("同一内容编号和版本已存在不同内容，请使用新版本");
    }
    Map<String,Object> saveResolved(byte[] bytes,ScapPackage source,ScapResolver.Resolved resolved,Long actor) {
        var content=resolved.content();var m=content.manifest();String code=m.path("code").asText(),version=m.path("version").asText();
        ScapStore.gate(jdbc,code);
        var existing=jdbc.queryForList("SELECT * FROM t_scap_package WHERE code=? AND version=?",code,version);
        if (!existing.isEmpty()) return sameSource(existing.get(0),source);
        String id=UUID.randomUUID().toString();
        jdbc.update("INSERT INTO t_scap_package(id,code,version,name,os_type,os_version_pattern,status,revision,source_sha256,source_zip,resolution,content_sha256,content_zip,metadata,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                id,code,version,m.path("name").asText(),m.path("osType").intValue(),m.path("osVersionPattern").asText(),"candidate",0,ScapPackage.digest(bytes),Base64.getEncoder().encodeToString(bytes),resolved.provenance(),content.sha256(),Base64.getEncoder().encodeToString(content.archive()),ScapStore.metadata(content),actor);
        jdbc.update("INSERT INTO t_scap_package_review(package_id,revision,action,note,actor) VALUES(?,?,?,?,?)",id,0,"import","导入离线内容，等待审核",actor);
        return detail(id);
    }
    @Transactional
    public Map<String,Object> decide(String id,Decision decision,Long actor) {
        ScapStore.actor(actor);
        if (decision==null||decision.revision()==null||decision.revision()<0||decision.action()==null) throw new IllegalArgumentException("缺少版本状态或审核操作");
        BaselineUpstreamGuard.lock(jdbc);
        if (List.of("approve","test","publish").contains(decision.action())) BaselineUpstreamGuard.requireAdoptable(jdbc,"scap",id);
        String note=ScapStore.note(decision.note());
        var row=ScapStore.one(jdbc,"SELECT * FROM t_scap_package WHERE id=?",id);
        ScapStore.gate(jdbc,row.get("code").toString());row=ScapStore.one(jdbc,"SELECT * FROM t_scap_package WHERE id=?",id);
        ScapStore.packageContent(row);
        int revision=((Number)row.get("revision")).intValue();
        if (decision.revision()!=revision) throw new IllegalArgumentException("内容状态已变化，请刷新后重试");
        String status=row.get("status").toString(),next=status,test=null;
        switch (decision.action()) {
            case "approve","reject" -> {
                if (!status.equals("candidate")) throw new IllegalArgumentException("仅待审核内容可批准或拒绝");
                next=decision.action().equals("approve")?"approved":"rejected";
            }
            case "test" -> {
                if (!status.equals("approved")) throw new IllegalArgumentException("仅已审核内容可下发测试");
                test=tasks.create(id,decision.agentIds(),"SCAP 内容测试",actor,true);
            }
            case "publish" -> {
                if (!status.equals("approved")||!ScapTaskService.testReady(jdbc,row.get("last_test_task")==null?null:row.get("last_test_task").toString()))
                    throw new IllegalArgumentException("需先完成当前候选内容的原生测试，排除执行异常和未知结果");
                var previous=jdbc.queryForList("SELECT id,revision FROM t_scap_package WHERE code=? AND status='published' AND id<>?",row.get("code"),id);
                for (var old:previous) {
                    int oldRevision=((Number)old.get("revision")).intValue()+1;
                    jdbc.update("UPDATE t_scap_package SET status='withdrawn',revision=? WHERE id=?",oldRevision,old.get("id"));
                    jdbc.update("INSERT INTO t_scap_package_review(package_id,revision,action,note,actor) VALUES(?,?,?,?,?)",old.get("id"),oldRevision,"superseded","由已测试版本替代: "+row.get("version"),actor);
                }
                next="published";
            }
            case "withdraw" -> {
                if (!List.of("approved","published").contains(status)) throw new IllegalArgumentException("仅已审核或已发布内容可撤回");
                next="withdrawn";
            }
            default -> throw new IllegalArgumentException("未知的 SCAP 内容操作");
        }
        if (jdbc.update("UPDATE t_scap_package SET status=?,revision=?,last_test_task=COALESCE(?,last_test_task) WHERE id=? AND revision=?",next,revision+1,test,id,revision)!=1)
            throw new IllegalArgumentException("内容状态已变化，请刷新后重试");
        jdbc.update("INSERT INTO t_scap_package_review(package_id,revision,action,note,actor) VALUES(?,?,?,?,?)",id,revision+1,decision.action(),note,actor);
        return detail(id);
    }
}
