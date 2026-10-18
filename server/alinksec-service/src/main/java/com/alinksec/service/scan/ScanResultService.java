package com.alinksec.service.scan;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.RptScanResult;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;
import java.security.MessageDigest;
import java.util.*;

/** First result, including zero findings, is immutable and bound to task membership. */
@Service
public class ScanResultService {
    public static final String DICTIONARY_VERSION="linux-common-v1";
    public static final String DICTIONARY_SHA256="53fc7bc25cc081fa37e598afbde408f68b066d5dc139e16fa31c7c9ce9640a40";
    private static final Set<String> STATUSES=Set.of("complete","partial","failed","unsupported","not_requested");
    private static final Set<String> ISSUES=Set.of("identity_read_failed","identity_metadata_invalid","identity_parse_failed","identity_duplicate","passwd_credential_source_unsupported","account_limit","identity_account_mismatch","hash_invalid","hash_unsupported","hash_cost_exceeded","hash_cost_unsupported","hash_verification_failed","scan_budget_exhausted","identity_changed","platform_unsupported");
    private static final Map<String,String> REMARKS=Map.of(
        "system_empty","本地 shadow 口令字段为空；是否允许认证取决于实际 PAM/服务策略",
        "system_weak","命中内置有限字典；口令与哈希均未回传",
        "uid0_nonroot","本地非 root 账户具有 UID=0，请人工核对用途",
        "pwd_stale","本地口令修改日期超过 90 天；不代表实际认证状态");
    private final JdbcTemplate jdbc;
    public ScanResultService(JdbcTemplate jdbc) {this.jdbc=jdbc;}

    @Transactional
    public void onResult(String agent,RptScanResult result) {
        long task;try {task=Long.parseLong(result.getTaskId());}catch(NumberFormatException e){return;}
        // Lock the parent task before inspecting or accepting member evidence.
        if(jdbc.update("UPDATE t_scan_task SET progress=progress WHERE id=?",task)!=1)return;
        var members=jdbc.queryForList("SELECT m.*,t.type,t.status FROM t_scan_task_agent m JOIN t_scan_task t ON t.id=m.task_id WHERE m.task_id=? AND m.agent_id=?",task,agent);
        if(members.size()!=1)return;
        var member=members.get(0);
        if(!String.valueOf(member.get("evidence_sha256")).isEmpty())return;
        int type=((Number)member.get("type")).intValue();boolean weak=(type&2)!=0,port=(type&4)!=0;
        if(result.getExecutionContract()!=1) {
            // Older Agents cannot echo command_id. A member may report only
            // unsupported failure in that format, never findings or a pass.
            if(String.valueOf(member.get("command_id")).isBlank() || !"pending".equals(member.get("state"))
                || !result.getCommandId().isBlank() && !result.getCommandId().equals(member.get("command_id")))return;
            jdbc.update("UPDATE t_scan_task_agent SET state='unsupported',weak_status=?,evidence=?,evidence_sha256=?,received_at=? WHERE task_id=? AND agent_id=?",weak?"unsupported":"not_requested",
                "{\"status\":\"unsupported\",\"issues\":[\"legacy_agent\"]}","9587af51dd11d6d9e45aef2d6371697f9d4748415ef97ab0d7050e978f85efeb",Instant.now().toString(),task,agent);
            advanceProgress(jdbc,task);return;
        }
        if(!result.getCommandId().equals(member.get("command_id")) || result.getCommandId().isBlank())return;
        var c=result.getWeakPasswordCoverage();
        if(result.getSerializedSize()>2<<20 || result.getWeakPasswordsCount()>maxFindings() || result.getPortServicesCount()>4096 || !STATUSES.contains(c.getStatus()) || c.getIssuesCount()>32 || c.getDurationMs()<0 || c.getDurationMs()>125000 || result.getVulnsCount()!=0)invalid();
        if(weak==c.getStatus().equals("not_requested") || (port?!Set.of("complete","failed").contains(result.getPortStatus()):!result.getPortStatus().equals("not_requested")))invalid();
        if(weak && !c.getStatus().equals("unsupported") && (!c.getDictionaryVersion().equals(DICTIONARY_VERSION) || !c.getDictionarySha256().equals(DICTIONARY_SHA256)))invalid();
        if((c.getStatus().equals("not_requested") || c.getStatus().equals("unsupported")) && (!c.getDictionaryVersion().isEmpty() || !c.getDictionarySha256().isEmpty() || c.getAccountsSeen()!=0 || c.getCandidatesTested()!=0))invalid();
        long seen=Integer.toUnsignedLong(c.getAccountsSeen()),checked=Integer.toUnsignedLong(c.getAccountsChecked()),excluded=Integer.toUnsignedLong(c.getAccountsExcluded()),unsupported=Integer.toUnsignedLong(c.getAccountsUnsupported()),failed=Integer.toUnsignedLong(c.getAccountsFailed());
        if(seen>4096 || checked+excluded+unsupported+failed!=seen || Integer.toUnsignedLong(c.getCandidatesTested())>10000 || c.getStatus().equals("complete") && (seen==0 || failed!=0 || unsupported!=0 || c.getIssuesCount()!=0))invalid();
        for(String issue:c.getIssuesList())if(!ISSUES.contains(issue))invalid();
        Set<String> keys=new HashSet<>();
        for(var f:result.getWeakPasswordsList()) {
            if(!weak || !f.getAccount().matches("[a-zA-Z0-9_.][a-zA-Z0-9_.@$-]{0,127}") || !REMARKS.containsKey(f.getType()) || !keys.add(f.getAccount()+":"+f.getType()))invalid();
            // The deprecated password field is deliberately never read, logged,
            // serialized, stored in a receipt or returned from this service.
        }
        if((c.getStatus().equals("failed") || c.getStatus().equals("unsupported")) && result.getWeakPasswordsCount()!=0)invalid();
        if(result.getWeakPasswordsCount()>3*seen)invalid();
        for(var p:result.getPortServicesList())if(!port || !result.getPortStatus().equals("complete") || p.getPort()<1 || p.getPort()>65535 || !Set.of("tcp","udp").contains(p.getProtocol()) || p.getProcess().length()>255 || p.getService().length()>128 || p.getRiskyReason().length()>1024)invalid();
        boolean complete=(!weak || c.getStatus().equals("complete")) && (!port || result.getPortStatus().equals("complete"));
        boolean late=!"pending".equals(member.get("state")) || ((Number)member.get("status")).intValue()!=1;
        Map<String,Object> evidence=new LinkedHashMap<>();
        evidence.put("dictionary_version",c.getDictionaryVersion());evidence.put("dictionary_sha256",c.getDictionarySha256());evidence.put("status",c.getStatus());
        evidence.put("accounts_seen",seen);evidence.put("accounts_checked",checked);evidence.put("accounts_excluded",excluded);evidence.put("accounts_unsupported",unsupported);evidence.put("accounts_failed",failed);evidence.put("candidates_tested",c.getCandidatesTested());evidence.put("duration_ms",c.getDurationMs());evidence.put("issues",c.getIssuesList());evidence.put("port_status",result.getPortStatus());
        evidence.put("findings",result.getWeakPasswordsList().stream().map(f->Map.of("account",f.getAccount(),"type",f.getType())).toList());
        String json=JsonUtils.write(evidence),digest;
        try{digest=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(json.getBytes(java.nio.charset.StandardCharsets.UTF_8)));}catch(Exception e){throw new IllegalStateException(e);}
        jdbc.update("UPDATE t_scan_task_agent SET state=?,weak_status=?,evidence=?,evidence_sha256=?,received_at=?,late=? WHERE task_id=? AND agent_id=?",complete?"complete":"partial",c.getStatus(),json,digest,Instant.now().toString(),late?1:0,task,agent);
        for(var f:result.getWeakPasswordsList())jdbc.update("INSERT INTO t_weakpwd_finding(task_id,agent_id,account,type,remark,status) VALUES(?,?,?,?,?,0)",task,agent,f.getAccount(),f.getType(),REMARKS.get(f.getType()));
        for(var p:result.getPortServicesList())jdbc.update("INSERT INTO t_port_finding(task_id,agent_id,port,protocol,process,service,risky,risky_reason) VALUES(?,?,?,?,?,?,?,?)",task,agent,p.getPort(),p.getProtocol(),p.getProcess(),p.getService(),p.getRisky(),p.getRiskyReason());
        advanceProgress(jdbc,task);
    }
    private static int maxFindings(){return 3*4096;}
    private static void invalid(){throw new IllegalArgumentException("安全扫描证据契约、范围或计数无效");}
    public static void advanceProgress(JdbcTemplate jdbc,long task) {
        int total=jdbc.queryForObject("SELECT count(*) FROM t_scan_task_agent WHERE task_id=?",Integer.class,task);
        if(total==0)return;
        int terminal=jdbc.queryForObject("SELECT count(*) FROM t_scan_task_agent WHERE task_id=? AND state<>'pending'",Integer.class,task);
        int failures=jdbc.queryForObject("SELECT count(*) FROM t_scan_task_agent WHERE task_id=? AND state NOT IN ('pending','complete')",Integer.class,task);
        jdbc.update("UPDATE t_scan_task SET progress=? WHERE id=? AND status=1",100*terminal/total,task);
        if(terminal==total)jdbc.update("UPDATE t_scan_task SET status=?,finished_at=CURRENT_TIMESTAMP WHERE id=? AND status=1",failures==0?2:3,task);
    }
}
