package com.alinksec.bootstrap;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.report.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.zip.*;
import java.io.*;
import javax.xml.parsers.DocumentBuilderFactory;
import static org.junit.jupiter.api.Assertions.*;

/** Identical real transactions, period boundaries and durable schedule scenarios on both databases. */
class ReportingIntegrationTest {
    @TempDir Path root;
    LibraryGovernanceIntegrationTest f;
    ComplianceReportService reports;
    long group;List<Long> tasks=new ArrayList<>();String linux,windows;
    @BeforeEach void setup()throws Exception {
        f=new LibraryGovernanceIntegrationTest();f.root=root;f.setup();
        reports=new ComplianceReportService(f.jdbc,f.dialect,f.manager);
        group=f.jdbc.queryForObject("INSERT INTO t_host_group(name) VALUES (?) RETURNING id",Long.class,"report-"+UUID.randomUUID());
    }
    @AfterEach void close() {
        if(f!=null && f.jdbc!=null) {
            f.jdbc.update("DELETE FROM t_report_schedule WHERE owner_id=?",f.actor);f.jdbc.update("DELETE FROM t_report_snapshot WHERE created_by=?",f.actor);
            for(long task:tasks){f.jdbc.update("DELETE FROM t_baseline_task_expected WHERE task_id=?",task);f.jdbc.update("DELETE FROM t_baseline_result WHERE task_id=?",task);f.jdbc.update("DELETE FROM t_baseline_summary WHERE task_id=?",task);f.jdbc.update("DELETE FROM t_baseline_task WHERE id=?",task);}
            for(String agent:f.agents){f.jdbc.update("DELETE FROM t_alert WHERE agent_id=?",agent);f.jdbc.update("DELETE FROM t_vuln_finding WHERE agent_id=?",agent);f.jdbc.update("DELETE FROM t_vuln_coverage WHERE agent_id=?",agent);}
            for(String agent:f.agents)f.jdbc.update("DELETE FROM t_agent WHERE agent_id=?",agent);
            f.jdbc.update("DELETE FROM t_host_group WHERE id=?",group);f.close();
        }
    }
    ReportQuery q(){return new ReportQuery("2026-02-01","2026-02-02",group,null);}
    String host(String hostname,int os,int status) {
        String id="report-"+UUID.randomUUID();f.agents.add(id);f.jdbc.update("INSERT INTO t_agent(agent_id,hostname,os_type,status,group_id) VALUES (?,?,?,?,?)",id,hostname,os,status,group);return id;
    }
    Object time(String utc){return f.dialect.timestamp(Instant.parse(utc));}
    void alert(String agent,String utc,int severity,int status) {
        f.jdbc.update("INSERT INTO t_alert(alert_no,agent_id,event_type,severity,title,detail,status,count,first_time,last_time) VALUES (?,?,'fixture',?,'Fixture','{}',?,4,?,?)",UUID.randomUUID().toString(),agent,severity,status,time(utc),time(utc));
    }
    void finding(String agent,String utc,int severity) {
        f.jdbc.update("INSERT INTO t_vuln_finding(task_id,agent_id,cve_id,software,installed_version,severity,created_at) VALUES (0,?,'CVE-2099-12345','fixture','1',?,?)",agent,severity,time(utc));
    }
    long task(String agent,String utc,int expected) {
        long id=f.jdbc.queryForObject("INSERT INTO t_baseline_task(task_no,name,scope,template_ids,created_at) VALUES (?,'Fixture','{}',? ,?) RETURNING id",Long.class,UUID.randomUUID().toString(),f.dialect.encodeLongList(List.of()),time(utc));tasks.add(id);
        for(int n=1;n<=expected;n++)f.jdbc.update("INSERT INTO t_baseline_task_expected(task_id,agent_id,item_id) VALUES (?,?,?)",id,agent,n);return id;
    }
    void outcome(long task,String agent,int item,String status) {
        f.jdbc.update("INSERT INTO t_baseline_result(task_id,agent_id,item_id,passed,execution_status) VALUES (?,?,?,?,?)",task,agent,item,status.equals("pass"),status);
    }
    @SuppressWarnings("unchecked") Map<String,Object> section(Map<String,Object> r,String key){return (Map<String,Object>)r.get(key);}
    @SuppressWarnings("unchecked") List<Map<String,Object>> rows(Map<String,Object> r,String key){return (List<Map<String,Object>>)r.get(key);}
    long number(Map<String,Object> r,String key){return ((Number)r.get(key)).longValue();}
    ComplianceReportService.ScheduleRequest plan(long revision){return new ComplianceReportService.ScheduleRequest("每周运营报表","weekly",7,group,null,true,revision);}
    String schedule(){return (String)reports.schedule(null,plan(0),f.actor).get("id");}
    void due(String id,Instant at){f.jdbc.update("UPDATE t_report_schedule SET next_run=?,retry_at=0 WHERE id=?",at.toEpochMilli(),id);}
    Map<String,Object> current(String id){return f.jdbc.queryForMap("SELECT * FROM t_report_schedule WHERE id=?",id);}

    @Test void emptyDatabaseHasZeroCountsAndNoFabricatedPassingRate() {
        var r=reports.preview(q());assertEquals(0,number(section(r,"assets"),"total"));assertEquals(0,number(section(r,"baseline"),"expected"));
        assertTrue(rows(r,"hosts").isEmpty());assertEquals(2,rows(r,"trend").size());
        for(String format:List.of("csv","xlsx","html","json"))assertTrue(ReportExport.render(r,format).length>100);
        assertTrue(new String(ReportExport.render(r,"csv"),StandardCharsets.UTF_8).contains("无可计算分母"));
    }
    @Test void inclusiveEndDayUsesShanghaiBoundariesAndExcludesDeletedAndOtherScopes() {
        linux=host("Linux",1,1);windows=host("Windows",2,2);String deleted=host("Deleted",1,1);f.jdbc.update("UPDATE t_agent SET deleted=true WHERE agent_id=?",deleted);
        for(String at:List.of("2026-01-31T15:59:59Z","2026-01-31T16:00:00Z","2026-02-02T15:59:59Z","2026-02-02T16:00:00Z")){alert(linux,at,5,2);finding(linux,at,5);}
        alert(windows,"2026-02-02T15:59:59Z",3,0);alert(deleted,"2026-02-02T15:59:59Z",5,0);
        var r=reports.preview(new ReportQuery(q().from(),q().to(),group,1));assertEquals(1,number(section(r,"assets"),"total"));
        assertEquals(2,number(rows(r,"alerts").get(0),"records"));assertEquals(8,number(rows(r,"alerts").get(0),"occurrences"));assertEquals(2,number(rows(r,"vulnerabilities").get(0),"records"));
        assertEquals(1,number(rows(r,"trend").get(0),"alerts"));assertEquals(1,number(rows(r,"trend").get(1),"alerts"));
        assertTrue(new String(ReportExport.render(r,"csv"),StandardCharsets.UTF_8).contains("危急（5）"));
    }
    @Test void secondPrecisionAtInclusiveLowerBoundaryIsNotDropped() {
        linux=host("Second precision",1,1);alert(linux,"2026-01-31T16:00:00Z",3,0);
        if(f.dialect.isSqlite())f.jdbc.update("UPDATE t_alert SET first_time='2026-01-31 16:00:00' WHERE agent_id=?",linux);
        else f.jdbc.update("UPDATE t_alert SET first_time=TIMESTAMPTZ '2026-01-31 16:00:00+00' WHERE agent_id=?",linux);
        assertEquals(1,number(rows(reports.preview(q()),"alerts").get(0),"records"));
    }
    @Test void invalidDatesScopeAndHeaderCharactersAreRejectedBeforeExport() {
        for(String day:List.of("2026-02-30","2026-2-01","2026-02-02\r\nX-Injected: yes","' OR 1=1"))assertThrows(IllegalArgumentException.class,()->reports.preview(new ReportQuery(day,"2026-02-02",group,null)));
        assertThrows(IllegalArgumentException.class,()->reports.preview(new ReportQuery("2024-01-01","2026-02-02",group,null)));
        assertThrows(IllegalArgumentException.class,()->reports.preview(new ReportQuery("2026-02-03","2026-02-02",group,null)));
        assertThrows(IllegalArgumentException.class,()->reports.preview(new ReportQuery(null,null,-1L,1)));
        assertThrows(IllegalArgumentException.class,()->reports.preview(new ReportQuery(null,null,group,3)));
        assertThrows(IllegalArgumentException.class,()->reports.preview(new ReportQuery(null,null,Long.MAX_VALUE,1)));
        var leap=new ReportQuery("2024-02-29","2024-02-29",group,null).checked(Instant.now());assertEquals(Duration.ofDays(1),Duration.between(leap.start(),leap.endExclusive()));
        assertEquals("2026-01-31T16:00:00Z",q().start().toString());
    }
    @Test void newerUnreportedAssignmentNeverFallsBackToEarlierPassingRound() {
        linux=host("Pending",1,1);long old=task(linux,"2026-02-01T00:00:00Z",1);outcome(old,linux,1,"pass");long newer=task(linux,"2026-02-02T00:00:00Z",3);
        var r=reports.preview(q());assertEquals(newer,number(rows(r,"hosts").get(0),"task_id"));assertEquals(0,number(section(r,"baseline"),"passed"));assertEquals(3,number(section(r,"baseline"),"pending"));
    }
    @Test void passFailErrorLegacyAndPendingRemainSeparateAndUnassignedHostsStayUnknown() {
        linux=host("Mixed",1,1);host("Not assigned",2,0);long id=task(linux,"2026-02-01T00:00:00Z",5);
        int i=1;for(String state:List.of("pass","fail","error","legacy"))outcome(id,linux,i++,state);
        var b=section(reports.preview(q()),"baseline");for(String key:List.of("passed","failed","errors","legacy","pending","unassessed_hosts"))assertEquals(1,number(b,key),key);assertEquals(5,number(b,"expected"));
    }
    @Test void historicalSummaryIsLegacyEvidenceEvenWhenItsOldScoreWasOneHundred() {
        linux=host("Legacy",1,1);long id=task(linux,"2026-02-01T00:00:00Z",0);
        f.jdbc.update("INSERT INTO t_baseline_summary(task_id,agent_id,total,passed_count,failed_count,score,checked_at) VALUES (?,?,5,5,0,100,?)",id,linux,time("2026-02-01T00:00:00Z"));
        var b=section(reports.preview(q()),"baseline");assertEquals(5,number(b,"legacy"));assertEquals(0,number(b,"passed"));
    }
    @Test void lateLegacySummaryDoesNotMoveAnOutOfPeriodTaskIntoSelection() {
        linux=host("Old task",1,1);long id=task(linux,"2026-01-30T00:00:00Z",0);
        f.jdbc.update("INSERT INTO t_baseline_summary(task_id,agent_id,total,passed_count,failed_count,score,checked_at) VALUES (?,?,5,5,0,100,?)",id,linux,time("2026-02-01T00:00:00Z"));
        var baseline=section(reports.preview(q()),"baseline");assertEquals(0,number(baseline,"assigned_hosts"));assertEquals(1,number(baseline,"unassessed_hosts"));assertEquals(0,number(baseline,"legacy"));
    }
    @Test void coverageDistinguishesNeverScannedStaleInventoryAndPendingSelection() {
        linux=host("Coverage",1,1);f.jdbc.update("UPDATE t_agent SET software_collection_status='complete',software_revision=2 WHERE agent_id=?",linux);
        assertEquals("not_scanned",rows(reports.preview(q()),"coverage").get(0).get("status"));
        f.jdbc.update("INSERT INTO t_vuln_coverage(agent_id,task_id,inventory_revision,rule_revision,status,software_count,assessment) VALUES (?,0,1,(SELECT revision FROM t_vuln_rule_state WHERE id=1),'complete',1,'{}')",linux);
        assertEquals("stale_inventory",rows(reports.preview(q()),"coverage").get(0).get("status"));
        f.jdbc.update("UPDATE t_vuln_coverage SET inventory_revision=2 WHERE agent_id=?",linux);
        long pending=f.jdbc.queryForObject("SELECT match_pending FROM t_security_selection_delivery WHERE id=1",Long.class);
        try {f.jdbc.update("UPDATE t_security_selection_delivery SET match_pending=1 WHERE id=1");assertEquals("selection_pending",rows(reports.preview(q()),"coverage").get(0).get("status"));}
        finally {f.jdbc.update("UPDATE t_security_selection_delivery SET match_pending=? WHERE id=1",pending);}
    }
    @Test void exportsPreserveQuotesNewlinesUnicodeAndNeutralizeFormulasWithoutExecutingMarkup()throws Exception {
        String hostile=" \t=HYPERLINK(\"https://invalid\",\"客户\")\n<img src=x onerror=alert(1)>";host(hostile,1,1);
        var r=reports.preview(q());String csv=new String(ReportExport.render(r,"csv"),StandardCharsets.UTF_8),html=new String(ReportExport.render(r,"html"),StandardCharsets.UTF_8);
        assertTrue(csv.startsWith("\uFEFF"));assertTrue(csv.contains("\"' \t=HYPERLINK(\"\"https://invalid\"\""));assertTrue(html.contains("&lt;img"));assertFalse(html.contains("<img"));assertFalse(html.contains("<script"));
        var factory=DocumentBuilderFactory.newInstance();factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);int sheets=0;
        try(var zip=new ZipInputStream(new ByteArrayInputStream(ReportExport.render(r,"xlsx")))) {
            ZipEntry entry;while((entry=zip.getNextEntry())!=null){byte[] content=zip.readAllBytes();var doc=factory.newDocumentBuilder().parse(new ByteArrayInputStream(content));assertEquals(0,doc.getElementsByTagName("f").getLength());if(entry.getName().startsWith("xl/worksheets/")){sheets++;assertTrue(doc.getElementsByTagName("row").getLength()>0);}if(entry.getName().equals("xl/worksheets/sheet2.xml"))assertTrue(new String(content,StandardCharsets.UTF_8).contains("客户"));}
        }assertEquals(7,sheets);
    }
    @Test void previewCommitmentIsStableAcrossGenerationTimesAndChangesWithStatistics() {
        linux=host("Committed",1,1);var first=reports.preview(q());assertEquals(first.get("dataDigest"),reports.preview(q()).get("dataDigest"));
        var saved=reports.save(q(),"New title",f.actor);assertEquals(first.get("dataDigest"),section(saved,"report").get("dataDigest"));assertEquals(saved.get("id"),section(saved,"report").get("snapshotId"));
        alert(linux,"2026-02-01T00:00:00Z",3,0);assertNotEquals(first.get("dataDigest"),reports.preview(q()).get("dataDigest"));
    }
    @Test void snapshotsRemainImmutableAfterDataChangesAndTamperingBlocksEveryExport() {
        linux=host("Before",1,1);var saved=reports.save(q(),"Independent report",f.actor);String id=(String)saved.get("id"),digest=(String)saved.get("sha256");
        f.jdbc.update("UPDATE t_agent SET hostname='After' WHERE agent_id=?",linux);var read=reports.snapshot(id);assertEquals(digest,read.get("sha256"));assertEquals("Before",rows(section(read,"report"),"hosts").get(0).get("hostname"));
        f.jdbc.update("UPDATE t_report_snapshot SET document='{}' WHERE id=?",id);assertThrows(IllegalStateException.class,()->reports.snapshot(id));
    }
    @Test void currentAccountAuthorityBlocksDisabledDemotedAndViewerWrites() {
        f.jdbc.update("UPDATE t_user SET status=0 WHERE id=?",f.actor);assertThrows(IllegalArgumentException.class,()->reports.save(q(),"Disabled",f.actor));
        f.jdbc.update("UPDATE t_user SET status=1,role_id=(SELECT id FROM t_role WHERE name='viewer') WHERE id=?",f.actor);assertThrows(IllegalArgumentException.class,()->reports.save(q(),"Viewer",f.actor));
        f.jdbc.update("UPDATE t_user SET role_id=(SELECT id FROM t_role WHERE name='operator') WHERE id=?",f.actor);var saved=reports.save(q(),"Operator",f.actor);assertNotNull(saved.get("id"));assertThrows(IllegalArgumentException.class,()->schedule());assertThrows(IllegalArgumentException.class,()->reports.delete((String)saved.get("id"),f.actor));
    }
    @Test void expiryPaginationCapacityAndRollbackStayBounded() {
        assertThrows(IllegalArgumentException.class,()->reports.history(0,20));assertThrows(IllegalArgumentException.class,()->reports.history(1,51));assertThrows(IllegalArgumentException.class,()->reports.snapshot("../secret"));
        var saved=reports.save(q(),"Expires",f.actor);String id=(String)saved.get("id");f.jdbc.update("UPDATE t_report_snapshot SET expires_at=0 WHERE id=?",id);assertThrows(IllegalArgumentException.class,()->reports.snapshot(id));
        f.tx.executeWithoutResult(s->{reports.save(q(),"Rolled back",f.actor);s.setRollbackOnly();});assertEquals(1,f.jdbc.queryForObject("SELECT COUNT(*) FROM t_report_snapshot WHERE created_by=?",Integer.class,f.actor));
        reports.runDue(Instant.now());assertEquals(0,f.jdbc.queryForObject("SELECT COUNT(*) FROM t_report_snapshot WHERE created_by=?",Integer.class,f.actor));
        for(int i=0;i<200;i++)f.jdbc.update("INSERT INTO t_report_snapshot(id,title,created_by,generated_at,expires_at,document,sha256) VALUES (?,'Capacity',?,?,?,'{}','unused')",UUID.randomUUID().toString(),f.actor,Instant.now().toEpochMilli(),Instant.now().plusSeconds(3600).toEpochMilli());
        assertThrows(IllegalArgumentException.class,()->reports.save(q(),"Over capacity",f.actor));assertEquals(200,number(reports.history(1,20),"total"));assertEquals(20,rows(reports.history(2,20),"list").size());
    }
    @Test void calendarPlansUseFixedShanghaiNineAmAcrossMonthAndYearBoundaries() {
        assertEquals("2026-02-01T01:00:00Z",ComplianceReportService.next("monthly",Instant.parse("2026-01-31T15:59:00Z")).toString());
        assertEquals("2026-02-02T01:00:00Z",ComplianceReportService.next("weekly",Instant.parse("2026-02-01T01:00:00Z")).toString());
        assertEquals("2027-01-01T01:00:00Z",ComplianceReportService.next("daily",Instant.parse("2026-12-31T02:00:00Z")).toString());
    }
    @Test void scheduleRestartGeneratesOneCompletedDayWindowAndCoalescesMissedSlots() {
        String id=schedule();Instant now=Instant.now(),slot=now.minus(Duration.ofDays(3));due(id,slot);
        new ComplianceReportService(f.jdbc,f.dialect,f.manager).runDue(now);reports.runDue(now);
        var plan=current(id);assertEquals(0,number(plan,"failures"));assertTrue(number(plan,"next_run")>now.toEpochMilli());
        var saved=reports.snapshot((String)plan.get("last_snapshot"));var query=section(section(saved,"report"),"query");LocalDate end=slot.atZone(ReportQuery.ZONE).toLocalDate().minusDays(1);
        assertEquals(end.toString(),query.get("to"));assertEquals(end.minusDays(6).toString(),query.get("from"));assertEquals(1,f.jdbc.queryForObject("SELECT COUNT(*) FROM t_report_snapshot WHERE schedule_id=?",Integer.class,id));
    }
    @Test void concurrentSchedulersCannotCommitTwoReportsForOneDueSlot()throws Exception {
        String id=schedule();Instant now=Instant.now();due(id,now.minusSeconds(1));var workers=Executors.newFixedThreadPool(2);var start=new CountDownLatch(1);
        try {var a=workers.submit(()->{start.await();reports.runDue(now);return null;});var b=workers.submit(()->{start.await();new ComplianceReportService(f.jdbc,f.dialect,f.manager).runDue(now);return null;});start.countDown();a.get(15,TimeUnit.SECONDS);b.get(15,TimeUnit.SECONDS);}
        finally {workers.shutdownNow();assertTrue(workers.awaitTermination(5,TimeUnit.SECONDS));}
        assertEquals(1,f.jdbc.queryForObject("SELECT COUNT(*) FROM t_report_snapshot WHERE schedule_id=?",Integer.class,id));assertEquals(0,number(current(id),"failures"));
    }
    @Test void failureIsDurableRetriedAtMostThreeTimesAndAdminCanReenableWithFreshRevision() {
        String id=schedule();Instant now=Instant.now();due(id,now.minusSeconds(1));f.jdbc.update("UPDATE t_report_schedule SET group_id=? WHERE id=?",Long.MAX_VALUE,id);
        reports.runDue(now);assertEquals(1,number(current(id),"failures"));reports.runDue(now.plusSeconds(1));assertEquals(1,number(current(id),"failures"));
        reports.runDue(now.plusSeconds(301));reports.runDue(now.plusSeconds(602));assertEquals(3,number(current(id),"failures"));assertEquals(0,number(current(id),"enabled"));assertFalse(current(id).get("last_error").toString().contains("SELECT"));
        reports.schedule(id,plan(1),f.actor);assertEquals(1,number(current(id),"enabled"));assertEquals(0,number(current(id),"failures"));assertThrows(IllegalArgumentException.class,()->reports.schedule(id,plan(1),f.actor));
        assertEquals(0,f.jdbc.queryForObject("SELECT COUNT(*) FROM t_report_snapshot WHERE schedule_id=?",Integer.class,id));
    }
    @Test void disabledOrDemotedOwnerImmediatelyStopsScheduledReports() {
        String id=schedule();Instant now=Instant.now();due(id,now.minusSeconds(1));f.jdbc.update("UPDATE t_user SET status=0 WHERE id=?",f.actor);reports.runDue(now);
        assertEquals(0,number(current(id),"enabled"));assertEquals(1,number(current(id),"failures"));assertTrue(current(id).get("last_error").toString().contains("所有者"));
    }
    @Test void boundedDetailsDiscloseTruncationWhileTotalsCoverAllHosts() {
        for(int i=0;i<501;i++)host("Host "+i,1,1);var r=reports.preview(q());assertEquals(501,number(section(r,"assets"),"total"));assertEquals(500,rows(r,"hosts").size());assertEquals(true,r.get("detailsTruncated"));assertEquals(501,number(section(r,"baseline"),"unassessed_hosts"));
    }
    @Test void captureActualPreviewHistoryAndScheduleForProductionBrowser()throws Exception {
        linux=host("=客户,清单\n<img src=x onerror=alert(1)>",1,1);windows=host("Windows 未回报",2,2);
        long id=task(linux,"2026-02-01T00:00:00Z",5);int n=1;for(String state:List.of("pass","fail","error","legacy"))outcome(id,linux,n++,state);task(windows,"2026-02-02T00:00:00Z",2);
        alert(linux,"2026-02-02T15:59:59Z",5,2);alert(windows,"2026-02-01T00:00:00Z",3,0);finding(linux,"2026-02-02T15:59:59Z",4);
        var preview=reports.preview(q());var saved=reports.save(q(),"客户安全运营周报",f.actor);String schedule=schedule();
        var out=new LinkedHashMap<String,Object>();out.put("database",f.dialect.isSqlite()?"sqlite":"postgres");out.put("group",group);out.put("preview",preview);out.put("snapshot",saved);out.put("history",reports.history(1,20));out.put("schedule",current(schedule));out.put("schedules",reports.schedules());
        out.put("updatedSchedule",reports.schedule(schedule,new ComplianceReportService.ScheduleRequest("每周运营报表 reviewed","weekly",7,group,null,true,1L),f.actor));
        String folder=System.getenv("ALINKSEC_REPORT_FIXTURES");if(folder==null)folder="../.tmp/report-fixtures";Path target=Path.of(folder).toAbsolutePath();Files.createDirectories(target);String database=(String)out.get("database");Files.writeString(target.resolve("console-"+database+".json"),JsonUtils.write(out));
        for(String format:List.of("csv","xlsx","html","json"))Files.write(target.resolve("report-"+database+"."+format),ReportExport.render(section(saved,"report"),format));
    }
}
