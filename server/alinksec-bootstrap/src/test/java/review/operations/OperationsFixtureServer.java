package review.operations;

import com.alinksec.bootstrap.BootstrapApplication;
import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.*;
import com.alinksec.service.cluster.BusinessReadiness;
import com.alinksec.service.report.ReportDispatcher;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.context.ApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.nio.file.*;
import java.util.*;
import java.util.concurrent.ThreadPoolExecutor;

/** Explicit test classpath only. Production startup never loads these controls. */
public final class OperationsFixtureServer {
    public static void main(String[] args) throws Exception {
        var app=(ServletWebServerApplicationContext)new SpringApplicationBuilder(BootstrapApplication.class).run(args);
        var probe=new Probe(app,app.getBean(JdbcTemplate.class));
        var mapping=app.getBean(RequestMappingHandlerMapping.class);
        for(var method:Probe.class.getDeclaredMethods()){
            var get=method.getAnnotation(GetMapping.class);var post=method.getAnnotation(PostMapping.class);
            if(get!=null||post!=null)mapping.registerMapping(RequestMappingInfo.paths("/api/review-operations"+(get!=null?get.value()[0]:post.value()[0]))
                    .methods(get!=null?RequestMethod.GET:RequestMethod.POST).options(mapping.getBuilderConfiguration()).build(),probe,method);
        }
        probe.initialize();
        Path control=Path.of(System.getenv("ALINKSEC_OPERATIONS_CONTROL_DIR"));
        var sampler=java.util.concurrent.Executors.newSingleThreadScheduledExecutor(task->{var thread=new Thread(task,"operations-probe-sampler");thread.setDaemon(true);return thread;});
        sampler.scheduleWithFixedDelay(()->{
            try {
                Path next=control.resolve("resources-next.json");
                Files.writeString(next,JsonUtils.write(probe.resources()));
                Files.move(next,control.resolve("resources-live.json"),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
            } catch(Exception failure){throw new IllegalStateException("fixture resource sampling failed",failure);}
        },0,100,java.util.concurrent.TimeUnit.MILLISECONDS);
        app.addApplicationListener(event->{if(event instanceof org.springframework.context.event.ContextClosedEvent)sampler.shutdownNow();});
        Files.writeString(Path.of(System.getenv("ALINKSEC_OPERATIONS_CONTROL_DIR"),"ready.json"),
                JsonUtils.write(Map.of("port",app.getWebServer().getPort(),"fixtureScope","test-classpath-only")));
    }
    @RestController
    @RequestMapping("/api/review-operations")
    public static class Probe {
        private final ApplicationContext app;
        private final JdbcTemplate jdbc;
        private static final Map<String,String> TABLES=Map.of("file_watch","t_file_watch_status","windows_login","t_windows_login_status",
                "clamav","t_clamav_status","yara","t_yara_status","scap","t_scap_status");
        public Probe(ApplicationContext app,JdbcTemplate jdbc){this.app=app;this.jdbc=jdbc;}
        void initialize(){
            var rules=app.getBean(com.alinksec.service.protect.ProtectRuleService.class);
            for(var rule:rules.listRules())rules.updateRule(String.valueOf(rule.get("rule_id")),Map.of("enabled",false));
            jdbc.update("INSERT INTO t_notify_channel(name,type,webhook_url,min_severity,enabled) VALUES('operations-local-sink','webhook',?,3,TRUE)",System.getenv("ALINKSEC_OPERATIONS_WEBHOOK"));
            var old=app.getBean(com.alinksec.service.config.DatabaseDialect.class).timestampBefore(java.time.Duration.ofSeconds(120));
            for(String kind:List.of("pending","disabled","deleted")){
                String id="ops-excluded-"+kind;
                jdbc.update("INSERT INTO t_agent(agent_id,hostname,ip,os_type,os_version,arch,status,deleted,last_heartbeat) VALUES(?,?,'127.0.0.1',1,'explicit scheduler exclusion fixture','amd64',?,?,?)",id,id,
                        kind.equals("pending")?0:kind.equals("disabled")?4:1,kind.equals("deleted"),kind.equals("pending")?null:old);
            }
        }
        private static String identity(String id){
            if(!id.matches("[0-9a-f-]{36}|ops-(engine-\\d{3}|responses)"))throw new IllegalArgumentException("fixture identity required");return id;
        }
        @GetMapping("/facts")
        public Map<String,Object> facts(@RequestParam String agent) {
            identity(agent);
            var hosts=jdbc.query("SELECT status,last_heartbeat,maintenance_until,offline_alerted FROM t_agent WHERE agent_id=?",(rs,i)->Map.of(
                    "status",rs.getInt(1),"lastHeartbeatMillis",rs.getTimestamp(2)==null?0:rs.getTimestamp(2).getTime(),
                    "maintenanceUntil",rs.getLong(3),"offlineAlerted",rs.getBoolean(4)),agent);
            var alerts=jdbc.queryForList("SELECT alert_no,status,count,first_time,last_time,action_taken,handle_remark,CAST(detail AS TEXT) AS detail FROM t_alert WHERE agent_id=? AND event_type='host_offline' ORDER BY first_time,alert_no",agent);
            var deliveries=jdbc.queryForList("SELECT alert_no,channel_id,attempts,delivered_at,lease_until FROM t_alert_notify_delivery WHERE alert_no IN (SELECT alert_no FROM t_alert WHERE agent_id=? AND event_type='host_offline') ORDER BY alert_no,channel_id",agent);
            var excluded=jdbc.queryForList("SELECT a.agent_id,a.status,a.deleted,count(t.id) AS alerts FROM t_agent a LEFT JOIN t_alert t ON t.agent_id=a.agent_id WHERE a.agent_id LIKE 'ops-excluded-%' GROUP BY a.agent_id,a.status,a.deleted ORDER BY a.agent_id");
            return Map.of("hosts",hosts,"alerts",alerts,"deliveries",deliveries,"excludedFixtures",excluded,"observedMillis",System.currentTimeMillis());
        }
        @PostMapping("/maintenance")
        public Map<String,Object> maintenance(@RequestBody Map<String,Object> body){
            String agent=identity(String.valueOf(body.get("agent")));long until=((Number)body.get("until")).longValue();
            if(until<0||until>System.currentTimeMillis()/1000+7200)throw new IllegalArgumentException("bounded maintenance required");
            return Map.of("updated",jdbc.update("UPDATE t_agent SET maintenance_until=? WHERE agent_id=?",until,agent));
        }
        @PostMapping("/exclude")
        public Map<String,Object> exclude(@RequestBody Map<String,Object> body){
            jdbc.update("UPDATE t_agent SET status=4,deleted=TRUE WHERE agent_id LIKE 'ops-excluded-%'");
            return Map.of("updated",jdbc.update("UPDATE t_agent SET status=4,deleted=TRUE WHERE agent_id=?",identity(String.valueOf(body.get("agent")))));
        }
        @GetMapping("/resources")
        public Map<String,Object> resources() throws Exception {
            var field=BusinessReadiness.class.getDeclaredField("probes");field.setAccessible(true);
            var executor=(ThreadPoolExecutor)field.get(app.getBean(BusinessReadiness.class));
            return Map.of("probeWorkers",executor.getPoolSize(),"probeQueue",executor.getQueue().size(),"probeQueueRemaining",executor.getQueue().remainingCapacity(),
                    "maximumPool",executor.getMaximumPoolSize());
        }
        @PostMapping("/engine-stage")
        public Map<String,Object> engines(@RequestBody Map<String,Object> body){
            String stage=String.valueOf(body.get("stage")),key=String.valueOf(body.getOrDefault("key","file_watch"));
            if(!Set.of("empty","healthy","linux-only","missing","failed","disabled","unsupported","stale-received","stale-probe","future-received","offline","global-off","partial","beyond-page").contains(stage)||!TABLES.containsKey(key))throw new IllegalArgumentException("known fixture stage required");
            for(String table:TABLES.values())jdbc.update("DELETE FROM "+table+" WHERE agent_id LIKE 'ops-engine-%'");
            jdbc.update("DELETE FROM t_agent WHERE agent_id LIKE 'ops-engine-%'");
            int count=stage.equals("empty")?0:stage.equals("beyond-page")?121:2;
            long now=System.currentTimeMillis();
            for(int i=0;i<count;i++){
                String id="ops-engine-"+String.format("%03d",i);
                jdbc.update("INSERT INTO t_agent(agent_id,hostname,ip,os_type,os_version,arch,status,protect_enabled,last_heartbeat,maintenance_until) VALUES(?,?,'127.0.0.1',?,'explicit database fixture','amd64',1,TRUE,CURRENT_TIMESTAMP,?)",id,id,stage.equals("linux-only")?1:2,now/1000+3600);
                var hb=heartbeat(now,null,null);
                if(stage.equals("linux-only"))hb=hb.toBuilder().setWindowsLoginContract(0).clearWindowsLoginStatus().build();
                app.getBean(com.alinksec.service.protect.FileWatchService.class).heartbeat(id,hb);
                app.getBean(com.alinksec.service.protect.WindowsLoginService.class).heartbeat(id,hb);
                app.getBean(com.alinksec.service.virus.ClamavService.class).heartbeat(id,hb);
                app.getBean(com.alinksec.service.virus.YaraService.class).heartbeat(id,hb);
                com.alinksec.service.baseline.ScapReadiness.heartbeat(jdbc,id,hb);
                if(stage.equals("missing")||Set.of("partial","beyond-page").contains(stage)&&i==count-1)jdbc.update("DELETE FROM "+TABLES.get(key)+" WHERE agent_id=?",id);
                if(Set.of("disabled","failed","unsupported","stale-probe").contains(stage)){
                    var changed=heartbeat(stage.equals("stale-probe")?now-400_000:now,key,stage);
                    switch(key){
                        case "file_watch"->app.getBean(com.alinksec.service.protect.FileWatchService.class).heartbeat(id,changed);
                        case "windows_login"->app.getBean(com.alinksec.service.protect.WindowsLoginService.class).heartbeat(id,changed);
                        case "clamav"->app.getBean(com.alinksec.service.virus.ClamavService.class).heartbeat(id,changed);
                        case "yara"->app.getBean(com.alinksec.service.virus.YaraService.class).heartbeat(id,changed);
                        case "scap"->com.alinksec.service.baseline.ScapReadiness.heartbeat(jdbc,id,changed);
                    }
                }
                if(stage.equals("stale-received")||stage.equals("future-received"))jdbc.update("UPDATE "+TABLES.get(key)+" SET observed_at=? WHERE agent_id=?",now+(stage.equals("stale-received")?-91_000:120_000),id);
                if(stage.equals("offline"))jdbc.update("UPDATE t_agent SET status=2 WHERE agent_id=?",id);
                if(stage.equals("global-off"))jdbc.update("UPDATE t_agent SET protect_enabled=FALSE WHERE agent_id=?",id);
            }
            var facts=new LinkedHashMap<String,Object>();
            for(var entry:TABLES.entrySet())facts.put(entry.getKey(),jdbc.queryForList("SELECT agent_id,contract,coverage,observed_at FROM "+entry.getValue()+" WHERE agent_id LIKE 'ops-engine-%' ORDER BY agent_id"));
            return Map.of("stage",stage,"engine",key,"fixtureScope","explicit-database-runtime-fixtures","hosts",jdbc.queryForList("SELECT agent_id,os_type,status,protect_enabled FROM t_agent WHERE agent_id LIKE 'ops-engine-%' ORDER BY agent_id"),"facts",facts);
        }
        private static RptHeartbeat heartbeat(long now,String changed,String stage){
            var file=new HashMap<String,Object>(Map.of("state","watching","issue","","recovery_issue","","backend","ReadDirectoryChangesW","recovering",false));
            for(String field:List.of("roots","watches"))file.put(field,1);
            for(String field:List.of("pending","dropped","gaps","last_event_at","last_sweep_at"))file.put(field,0);
            file.put("last_sync_at",now);
            var login=new HashMap<String,Object>(Map.of("state","polling","issue","","audit_success",true,"audit_failure",true));
            for(String field:List.of("last_event_at","cursor","active_blocks","block_failures","coverage_gaps","discarded_events","rules","retained_events"))login.put(field,0);
            login.put("last_poll_at",now);
            var clam=new HashMap<String,Object>(Map.of("state","ready","version","ClamAV 1.4.6/fixture","last_issue","","realtime",false,"observed_at",now/1000,"last_scan_at",0,"scans",0,"failures",0));
            var yara=new HashMap<String,Object>(clam);yara.put("version","YARA 4.5.8/sha256:"+"a".repeat(64));
            var scap=new HashMap<String,Object>(Map.of("state","ready","version","5.15","runtime_sha256","a".repeat(64),"last_issue","","observed_at",now/1000));
            var selected=Map.of("file_watch",file,"windows_login",login,"clamav",clam,"yara",yara,"scap",scap);
            if(changed!=null&&Set.of("disabled","failed").contains(stage))selected.get(changed).put("state",stage.equals("disabled")?"disabled":changed.equals("file_watch")?"degraded":changed.equals("windows_login")?"failed":"unavailable");
            var hb=RptHeartbeat.newBuilder().setFileWatchContract(1).setFileWatchStatus(JsonUtils.write(file)).setWindowsLoginContract(1).setWindowsLoginStatus(JsonUtils.write(login))
                    .setClamavContract(1).setClamavStatus(JsonUtils.write(clam)).setYaraContract(1).setYaraStatus(JsonUtils.write(yara)).setScapContract(1).setScapStatus(JsonUtils.write(scap));
            if("unsupported".equals(stage))switch(changed){case "file_watch"->hb.setFileWatchContract(0);case "windows_login"->hb.setWindowsLoginContract(0);case "clamav"->hb.setClamavContract(0);case "yara"->hb.setYaraContract(0);case "scap"->hb.setScapContract(0);}
            return hb.build();
        }
        @PostMapping("/responses")
        public Map<String,Object> responses(){
            String id="ops-responses";
            jdbc.update("INSERT INTO t_agent(agent_id,hostname,ip,os_type,os_version,arch,status) VALUES(?,?,'127.0.0.1',2,'explicit report fixture','amd64',1) ON CONFLICT(agent_id) DO NOTHING",id,id);
            var reports=new ArrayList<Map<String,Object>>();var dispatcher=app.getBean(ReportDispatcher.class);
            for(int i=0;i<64;i++){
                String action=i<60?(i%2==0?"killed":"alert_only"):List.of("kill_failed","queued","sent","running").get(i-60);
                var report=Report.newBuilder().setAgentId(id).setReportId(UUID.randomUUID().toString()).setReliable(true).setSecurityEvent(RptSecurityEvent.newBuilder().setRuleId("ops-response-"+i).setRuleName("Explicit aggregation fixture").setType("process").setSeverity(Severity.SEV_LOW).setActionTaken(action)).build();
                dispatcher.dispatch(id,report);dispatcher.dispatch(id,report);
                reports.add(Map.of("reportId",report.getReportId(),"action",action,"protobufBase64",Base64.getEncoder().encodeToString(report.toByteArray()),"dispatches",2));
                if(i<6&&i%2==0)jdbc.update("UPDATE t_automatic_response SET received_at=? WHERE agent_id=? AND report_id=?",System.currentTimeMillis()-java.time.Duration.ofDays(31).toMillis(),id,report.getReportId());
            }
            jdbc.update("UPDATE t_agent SET isolation_contract=1 WHERE agent_id=?",id);
            var leases=app.getBean(com.alinksec.service.protect.IsolationLeaseService.class);
            var pulse=RptIsolationState.newBuilder().setLeaseId("a".repeat(32)).setGeneration(1).setRevision(1).setCommandId("local-"+"a".repeat(32)).setPhase("applying").setDeadline(System.currentTimeMillis()+10_000).setAutomatic(true);
            var isolation=new ArrayList<Map<String,Object>>();
            for(String phase:List.of("applying","unconfirmed-active","confirmed-active","duplicate-confirmed-active")){
                if(!phase.equals("applying"))pulse.setPhase("active").setNonce("b".repeat(32)).setRevision(phase.equals("unconfirmed-active")?2:3).setConfirmed(!phase.equals("unconfirmed-active"));
                leases.observe(id,pulse.build());
                isolation.add(Map.of("phase",phase,"pulseBase64",Base64.getEncoder().encodeToString(pulse.build().toByteArray()),"facts",jdbc.queryForList("SELECT report_id,action FROM t_automatic_response WHERE agent_id=? AND action='isolated'",id)));
            }
            for(String status:List.of("pending","sent","done","failed"))jdbc.update("INSERT INTO t_command(cmd_id,agent_id,type,payload,status) VALUES(?,?, 'protect_action','{}',?)","ops-manual-"+status,id,Map.of("pending",0,"sent",1,"done",4,"failed",5).get(status));
            long midnight=java.time.LocalDate.now(java.time.ZoneId.of("Asia/Shanghai")).atStartOfDay(java.time.ZoneId.of("Asia/Shanghai")).toInstant().toEpochMilli();
            jdbc.update("INSERT INTO t_automatic_response(agent_id,report_id,action,received_at) VALUES(?,?,'killed',?)",id,"ops-before-midnight",midnight-1);
            jdbc.update("INSERT INTO t_automatic_response(agent_id,report_id,action,received_at) VALUES(?,?,'killed',?)",id,"ops-at-midnight",midnight);
            jdbc.update("INSERT INTO t_automatic_response(agent_id,report_id,action,received_at) VALUES(?,?,'killed',?)",id,"ops-future",System.currentTimeMillis()+java.time.Duration.ofDays(1).toMillis());
            jdbc.update("UPDATE t_agent SET status=4,deleted=TRUE WHERE agent_id=?",id);
            return Map.of("reports",reports,"isolation",isolation,"facts",jdbc.queryForList("SELECT agent_id,report_id,action,received_at FROM t_automatic_response ORDER BY agent_id,report_id"),
                    "commands",jdbc.queryForList("SELECT cmd_id,status FROM t_command WHERE agent_id=? ORDER BY cmd_id",id),"fixtureScope","explicit-report-and-timestamp-fixtures");
        }
        @GetMapping("/response-sql")
        public Map<String,Object> responseSql(@RequestParam long from,@RequestParam long through){
            if(from<0||through<from)throw new IllegalArgumentException("valid bounded window required");
            return Map.of("count",jdbc.queryForObject("SELECT count(*) FROM t_automatic_response WHERE received_at>=? AND received_at<=?",Long.class,from,through),
                    "facts",jdbc.queryForList("SELECT agent_id,report_id,action,received_at FROM t_automatic_response ORDER BY agent_id,report_id"));
        }
    }
}
