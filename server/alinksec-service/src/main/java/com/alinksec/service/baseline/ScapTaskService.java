package com.alinksec.service.baseline;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.CmdScapScan;
import com.alinksec.proto.Command;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.config.DatabaseDialect;
import com.google.protobuf.ByteString;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class ScapTaskService {
    private final JdbcTemplate jdbc;
    private final CommandService commands;
    private final DatabaseDialect database;
    public ScapTaskService(JdbcTemplate jdbc,CommandService commands,DatabaseDialect database) {this.jdbc=jdbc;this.commands=commands;this.database=database;}

    @Transactional
    public String create(String packageId,List<String> agents,String name,Long actor,boolean test) {
        ScapStore.actor(actor);
        if (agents==null || agents.isEmpty() || agents.size()>(test?10:20) || agents.stream().anyMatch(id->id==null||id.isBlank())
                || agents.stream().distinct().count()!=agents.size()) throw new IllegalArgumentException(test?"请选择 1 至 10 台不同测试主机":"请选择 1 至 20 台不同核查主机");
        if (name!=null&&name.length()>128) throw new IllegalArgumentException("任务名称最多 128 字");
        var row=ScapStore.one(jdbc,"SELECT * FROM t_scap_package WHERE id=?",packageId);
        ScapStore.gate(jdbc,row.get("code").toString());
        row=ScapStore.one(jdbc,"SELECT * FROM t_scap_package WHERE id=?",packageId);
        if (!row.get("status").equals(test?"approved":"published")) throw new IllegalArgumentException(test?"仅已审核的候选内容可测试":"仅已发布内容可创建核查任务");
        var content=ScapStore.packageContent(row);
        var manifest=content.manifest();
        var pattern=com.google.re2j.Pattern.compile(manifest.path("osVersionPattern").asText());
        List<Map<String,Object>> targets=new ArrayList<>();
        for (String agent:agents) {
            var target=ScapReadiness.requireReady(jdbc,agent);
            if (((Number)target.get("os_type")).intValue()!=manifest.path("osType").intValue()
                    || !pattern.matcher(java.util.Objects.toString(target.get("os_version"),"")).matches())
                throw new IllegalArgumentException("内容不适用于所选主机: "+agent);
            targets.add(target);
        }
        Map<String,Object> snapshot=new LinkedHashMap<>();
        snapshot.put("packageId",packageId);snapshot.put("sourceSha256",row.get("source_sha256"));
        snapshot.put("contentSha256",content.sha256());snapshot.put("content",JsonUtils.read(ScapStore.metadata(content)));
        snapshot.put("agentIds",List.copyOf(agents));
        Map<String,String> runtimePins=new LinkedHashMap<>();
        for (var target:targets) runtimePins.put(target.get("agent_id").toString(),JsonUtils.read(target.get("coverage").toString()).path("runtime_sha256").asText());
        snapshot.put("runtimePins",runtimePins);
        String saved=JsonUtils.write(snapshot),task=UUID.randomUUID().toString();
        String encoded=Base64.getEncoder().encodeToString(content.archive());
        jdbc.update("INSERT INTO t_scap_task(id,name,package_id,content_zip,content_sha256,snapshot,snapshot_sha256,test_mode,state,created_by) VALUES(?,?,?,?,?,?,?,?,?,?)",
                task,name==null||name.isBlank()?(test?"SCAP 内容测试":"SCAP 基线核查"):name.strip(),packageId,encoded,content.sha256(),saved,ScapStore.digest(saved),test,"running",actor);
        ByteString archive=ByteString.copyFrom(content.archive());
        for (var target:targets) {
            String agent=target.get("agent_id").toString();
            String runtime=JsonUtils.read(target.get("coverage").toString()).path("runtime_sha256").asText();
            var command=CmdScapScan.newBuilder().setTaskId(task).setExecutionContract(1).setContentZip(archive)
                    .setContentSha256(content.sha256()).setBenchmarkId(manifest.path("benchmarkId").asText())
                    .setProfileId(manifest.path("profileId").asText()).setRuntimeSha256(runtime);
            String commandId=commands.dispatchAfterCommit(agent,Command.newBuilder().setScapScan(command),actor);
            jdbc.update("INSERT INTO t_scap_task_agent(task_id,agent_id,command_id,runtime_sha256,state) VALUES(?,?,?,?,?)",task,agent,commandId,runtime,"pending");
        }
        return task;
    }

    public Map<String,Object> list(int page,int size) {
        if (page<1||page>100000||size<1||size>100) throw new IllegalArgumentException("分页参数无效");
        var rows=jdbc.queryForList("SELECT id,name,package_id,state,test_mode,created_by,created_at,finished_at FROM t_scap_task ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?",size,(page-1)*size);
        for (var row:rows) row.put("hosts",jdbc.queryForList("SELECT agent_id,state,issue FROM t_scap_task_agent WHERE task_id=? ORDER BY agent_id",row.get("id")));
        return Map.of("items",rows,"total",jdbc.queryForObject("SELECT count(*) FROM t_scap_task",Long.class),"page",page,"page_size",size);
    }
    public Map<String,Object> detail(String task) {
        var row=ScapStore.one(jdbc,"SELECT * FROM t_scap_task WHERE id=?",task);
        var snapshot=ScapStore.taskSnapshot(row);
        row.remove("content_zip");row.remove("snapshot_sha256");row.put("snapshot",snapshot);
        var hosts=jdbc.queryForList("SELECT agent_id,command_id,runtime_sha256,state,issue,evidence_sha256,evidence,finished_at FROM t_scap_task_agent WHERE task_id=? ORDER BY agent_id",task);
        for (var host:hosts) host.put("evidence",JsonUtils.read(host.get("evidence").toString()));
        row.put("hosts",hosts);return row;
    }
    public byte[] content(String task) {
        var row=ScapStore.one(jdbc,"SELECT * FROM t_scap_task WHERE id=?",task);ScapStore.taskSnapshot(row);
        return Base64.getDecoder().decode(row.get("content_zip").toString());
    }
    public static boolean testReady(JdbcTemplate jdbc,String task) {
        if (task==null) return false;
        var tasks=jdbc.queryForList("SELECT * FROM t_scap_task WHERE id=?",task);
        if (tasks.size()!=1) return false;
        var snapshot=ScapStore.taskSnapshot(tasks.get(0));
        var rows=jdbc.queryForList("SELECT agent_id,state,evidence_sha256,evidence FROM t_scap_task_agent WHERE task_id=?",task);
        if (rows.isEmpty()) return false;
        var expected=new java.util.HashSet<String>();snapshot.path("agentIds").forEach(id->expected.add(id.asText()));
        if (!expected.equals(new java.util.HashSet<>(rows.stream().map(row->row.get("agent_id").toString()).toList()))) return false;
        for (var row:rows) {
            var evidence=JsonUtils.read(row.get("evidence").toString());
            if (!ScapStore.digest(row.get("evidence").toString()).equals(row.get("evidence_sha256")) || !row.get("state").equals("complete") || evidence.path("counts").path("error").asInt(-1)!=0
                    || evidence.path("counts").path("unknown").asInt(-1)!=0) return false;
        }
        return true;
    }
    @Scheduled(fixedDelay=60000,initialDelay=90000)
    @Transactional
    public void sweepTimeout() {
        var tasks=jdbc.queryForList("SELECT id FROM t_scap_task WHERE state='running' AND created_at<?",String.class,database.timestampBefore(Duration.ofMinutes(30)));
        for (String task:tasks) {
            jdbc.update("UPDATE t_scap_task SET state=state WHERE id=?",task);
            jdbc.update("UPDATE t_scap_task_agent SET state='timeout',issue='task_timeout',finished_at=CURRENT_TIMESTAMP WHERE task_id=? AND state='pending' AND evidence_sha256=''",task);
            ScapStore.advance(jdbc,task);
        }
    }
}
