package com.alinksec.bootstrap;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.RptSecurityEvent;
import com.alinksec.service.alert.SecurityEventService;
import com.alinksec.service.geo.GeoIpProperties;
import com.alinksec.service.geo.GeoIpService;
import com.alinksec.service.geo.ScreenSituationService;
import com.alinksec.service.notify.NotifyService;
import com.alinksec.service.query.*;
import com.alinksec.service.report.*;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

/** Same source-aware rows, real queries and loopback delivery on both databases. */
class AlertSeverityIntegrationTest {
    @TempDir Path root;
    LibraryGovernanceIntegrationTest f;
    String agent;
    SecurityEventService events;
    List<Long> channels = new ArrayList<>();
    @BeforeEach void setup() throws Exception {
        f = new LibraryGovernanceIntegrationTest(); f.root = root; f.setup();
        agent = "severity-" + UUID.randomUUID(); f.agents.add(agent);
        f.jdbc.update("INSERT INTO t_agent(agent_id,hostname,os_type,status) VALUES(?, '等级验收主机',1,1)",agent);
        events = new SecurityEventService(f.jdbc,mock(NotifyService.class),f.dialect);
    }
    @AfterEach void close() {
        if (f != null && f.jdbc != null) {
            f.jdbc.update("DELETE FROM t_alert_notify_delivery WHERE alert_no IN (SELECT alert_no FROM t_alert WHERE agent_id=?)",agent);
            f.jdbc.update("DELETE FROM t_alert WHERE agent_id=?",agent);
            for (long id : channels) f.jdbc.update("DELETE FROM t_notify_channel WHERE id=?",id);
            f.jdbc.update("DELETE FROM t_report_snapshot WHERE created_by=?",f.actor);
            f.close();
        }
    }
    void event(String rule,int raw) {
        events.onEvent(agent,RptSecurityEvent.newBuilder().setType("process").setRuleId(rule)
                .setRuleName(rule).setSeverityValue(raw).setDetail("{\"process_key\":\"123:456\",\"severity_source\":\"legacy_unclassified\"}").build());
    }
    long n(Map<String,Object> row,String key) { return ((Number)row.get(key)).longValue(); }
    Map<String,Object> row(String rule) { return f.jdbc.queryForMap("SELECT * FROM v_alert_severity WHERE agent_id=? AND rule_id=?",agent,rule); }
    @SuppressWarnings("unchecked") List<Map<String,Object>> rows(Object value) { return (List<Map<String,Object>>)value; }

    @Test void rawValuesSourcesAggregationQueriesAndSnapshotsStayConsistent() throws Exception {
        String legacy = "legacy-"+UUID.randomUUID();
        f.jdbc.update("INSERT INTO t_alert(alert_no,agent_id,rule_id,event_type,severity,title,detail) VALUES(?,?,'same','process',4,'Historical','{\"fingerprint\":\"process:same:123:456\"}')",legacy,agent);
        event("same",4); event("same",4); event("critical",5); event("medium",3); event("low",2); event("info",1); event("unspecified",0); event("future",99);
        assertEquals(4,n(f.jdbc.queryForMap("SELECT * FROM v_alert_severity WHERE alert_no=?",legacy),"severity_level"));
        assertEquals(1,f.jdbc.queryForObject("SELECT count FROM t_alert WHERE alert_no=?",Integer.class,legacy));
        var high=f.jdbc.queryForMap("SELECT * FROM v_alert_severity WHERE agent_id=? AND rule_id='same' AND severity_source='agent_proto_v1'",agent);
        assertEquals(4,n(high,"severity")); assertEquals(3,n(high,"severity_level")); assertEquals(2,n(high,"count"));
        for (var value:Map.of("critical",4,"medium",2,"low",1,"info",0,"unspecified",-1,"future",-1).entrySet()) assertEquals(value.getValue().longValue(),n(row(value.getKey()),"severity_level"));
        event("changing",3);event("changing",4);
        assertEquals(2,f.jdbc.queryForObject("SELECT COUNT(*) FROM t_alert WHERE agent_id=? AND rule_id='changing'",Integer.class,agent));
        var queries=new AlertQueryService(f.jdbc);
        var filtered=rows(queries.list(null,3,agent,null,1,100).get("list"));
        assertEquals(4,filtered.size()); assertTrue(filtered.stream().allMatch(a->n(a,"severity_level")>=3));
        var summary=new DashboardQueryService(f.jdbc,f.dialect).summary();
        @SuppressWarnings("unchecked") var counts=(Map<String,Object>)summary.get("alerts");
        assertEquals(2,n(counts,"criticalOpen")); assertEquals(1,n(counts,"legacyUnclassifiedOpen"));
        var reports=new ComplianceReportService(f.jdbc,f.dialect,f.manager);
        String today=LocalDate.now(ZoneId.of("Asia/Shanghai")).toString();var q=new ReportQuery(today,today,null,null);
        var preview=reports.preview(q);var alertRows=rows(preview.get("alerts"));
        assertTrue(alertRows.stream().anyMatch(a->a.get("severity_label").equals("高危（原值 4）") && a.get("severity_source").equals("agent_proto_v1")));
        assertTrue(alertRows.stream().anyMatch(a->a.get("severity_label").toString().contains("严重（4） · 历史记录")));
        for(String format:List.of("csv","html")) {
            String exported=new String(ReportExport.render(preview,format),StandardCharsets.UTF_8);
            assertTrue(exported.contains("高危（原值 4）"));assertTrue(exported.contains("历史记录，沿用旧含义"));
        }
        var saved=reports.save(q,"来源等级验收",f.actor);String id=saved.get("id").toString(),digest=saved.get("sha256").toString();
        f.jdbc.update("UPDATE t_alert SET severity=1 WHERE alert_no=?",legacy);
        assertEquals(digest,reports.snapshot(id).get("sha256"));assertEquals(saved.get("report"),reports.snapshot(id).get("report"));
        f.jdbc.update("UPDATE t_alert SET severity=4 WHERE alert_no=?",legacy);
        String directory=System.getenv("ALINKSEC_SEVERITY_FIXTURES");
        if(directory!=null&&!directory.isBlank()) {
            Path dst=Path.of(directory);Files.createDirectories(dst);String database=f.dialect.isSqlite()?"sqlite":"postgres";
            Files.writeString(dst.resolve("severity-"+database+".json"),JsonUtils.write(Map.of("database",database,"alerts",queries.list(null,null,agent,null,1,100),"summary",summary,"report",preview,"snapshot",saved))+"\n");
        }
    }

    @Test void immediateAndRetriedNotificationsUseDeclaredLevelsAndKeepRawValues() throws Exception {
        var captured=new CopyOnWriteArrayList<Map<String,Object>>();var response=new AtomicInteger(503);
        var http=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        http.createContext("/",exchange->{try {
            captured.add(Map.of("path",exchange.getRequestURI().getPath(),"key",exchange.getRequestHeaders().getFirst("Idempotency-Key"),"body",JsonUtils.read(new String(exchange.getRequestBody().readAllBytes(),StandardCharsets.UTF_8))));
            exchange.sendResponseHeaders(response.get(),-1);
        }finally{exchange.close();}});http.start();
        try {
            for(int level:List.of(3,4)) channels.add(f.jdbc.queryForObject("INSERT INTO t_notify_channel(name,webhook_url,min_severity) VALUES(?,?,?) RETURNING id",Long.class,"severity-"+UUID.randomUUID(),"http://127.0.0.1:"+http.getAddress().getPort()+"/level"+level,level));
            var notify=new NotifyService(f.jdbc);
            event("medium",3);event("high",4);event("critical",5);
            String high=row("high").get("alert_no").toString();
            notify.onAlert(row("medium").get("alert_no").toString());assertTrue(captured.isEmpty());
            notify.onAlert(high);assertEquals(1,captured.size());assertEquals("/level3",captured.getFirst().get("path"));
            var body=(com.fasterxml.jackson.databind.JsonNode)captured.getFirst().get("body");
            assertEquals(4,body.path("alinksec").path("severity").asInt());assertEquals(3,body.path("alinksec").path("severityLevel").asInt());
            assertEquals("agent_proto_v1",body.path("alinksec").path("severitySource").asText());
            f.jdbc.update("UPDATE t_alert_notify_delivery SET next_attempt_at=0 WHERE alert_no=?",high);response.set(204);
            // Retry uses the same database view, and also processes the pending critical alert.
            notify.retryRecent();assertEquals(4,captured.size());
            var highRequests=captured.stream().filter(a->((com.fasterxml.jackson.databind.JsonNode)a.get("body")).path("alinksec").path("alertNo").asText().equals(high)).toList();
            assertEquals(2,highRequests.size());assertEquals(highRequests.get(0).get("key"),highRequests.get(1).get("key"));
            assertEquals(2,f.jdbc.queryForObject("SELECT attempts FROM t_alert_notify_delivery WHERE alert_no=?",Integer.class,high));
            assertEquals(0,f.jdbc.queryForObject("SELECT COUNT(*) FROM t_alert_notify_delivery WHERE alert_no=? AND channel_id=?",Integer.class,high,channels.get(1)));
        }finally{http.stop(0);}
    }

    @Test void geographicSnapshotKeepsObservedLoginSourceAndDatabaseHostIdentity() {
        f.jdbc.update("UPDATE t_agent SET ip='10.20.30.40' WHERE agent_id=?",agent);
        events.onEvent(agent,RptSecurityEvent.newBuilder().setType("login_crack").setRuleId("geo-login")
                .setSeverityValue(4).setDetail("{\"source_ip\":\"192.168.2.8\",\"hostname\":\"untrusted\"}").build());
        var query=new AlertQueryService(f.jdbc);
        var row=rows(query.list(null,null,agent,null,1,20).get("list")).getFirst();
        assertEquals("10.20.30.40",row.get("host_ip")); assertEquals("等级验收主机",row.get("hostname"));
        try(var geo=new GeoIpService(new GeoIpProperties())) {
            var data=new ScreenSituationService(query,geo).snapshot();
            var event=rows(data.get("events")).stream().filter(e->n(e,"id")==n(row,"id")).findFirst().orElseThrow();
            var source=(Map<?,?>)event.get("source");var target=(Map<?,?>)event.get("target");
            assertEquals("192.168.2.8",source.get("ip")); assertEquals("non_public_ip",((Map<?,?>)source.get("location")).get("status"));
            assertEquals(agent,target.get("agentId"));assertEquals("10.20.30.40",target.get("ip"));
            assertFalse(((Map<?,?>)target.get("location")).containsKey("latitude"));
        }
    }
    @Test void webAttackAggregationKeepsDifferentAttackSourcesSeparate() {
        for (String type : List.of("web_attack", "sql_injection", "xss")) {
            for (String ip : List.of("192.168.2.8", "192.168.2.9", "192.168.2.8")) {
                events.onEvent(agent,RptSecurityEvent.newBuilder().setType(type).setRuleId("web-"+type).setSeverityValue(4)
                        .setDetail("{\"source_ip\":\""+ip+"\",\"request\":\"GET /example\"}").build());
            }
            var actual=f.jdbc.queryForList("SELECT detail, count FROM t_alert WHERE agent_id=? AND event_type=?", agent, type);
            assertEquals(2,actual.size());
            assertEquals(3,actual.stream().mapToInt(r->((Number)r.get("count")).intValue()).sum());
        }
        try(var geo=new GeoIpService(new GeoIpProperties())) {
            var snapshot=new ScreenSituationService(new AlertQueryService(f.jdbc),geo).snapshot();
            assertEquals(6,rows(snapshot.get("events")).stream().filter(e->Boolean.TRUE.equals(e.get("network"))).count());
        }
    }
}
