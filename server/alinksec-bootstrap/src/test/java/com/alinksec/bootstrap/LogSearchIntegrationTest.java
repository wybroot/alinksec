package com.alinksec.bootstrap;

import com.alinksec.common.util.*;
import com.alinksec.proto.*;
import com.alinksec.service.log.*;
import com.alinksec.gateway.rest.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;

/** Same real transactional, literal-query and REST evidence on SQLite/restricted PostgreSQL. */
class LogSearchIntegrationTest {
    @TempDir Path root;
    LibraryGovernanceIntegrationTest f;LogBatchService intake;LogSearchService search;String agent;
    long from,to;
    @BeforeEach void setup()throws Exception {
        f=new LibraryGovernanceIntegrationTest();f.root=root;f.setup();intake=new LogBatchService(f.jdbc,f.dialect);search=new LogSearchService(f.jdbc,f.dialect,f.manager);
        agent="raw-"+UUID.randomUUID();f.agents.add(agent);f.jdbc.update("INSERT INTO t_agent(agent_id,hostname,os_type) VALUES (?,'Raw fixture',1)",agent);
        to=System.currentTimeMillis()+60000;from=to-3600000;
    }
    @AfterEach void close(){if(f!=null && f.jdbc!=null){
        f.tx.executeWithoutResult(s->{LogBatchService.gate(f.jdbc);var usage=f.jdbc.queryForMap("SELECT COUNT(*) AS rows,COALESCE(SUM(stored_bytes),0) AS bytes FROM t_agent_log WHERE agent_id=?",agent);f.jdbc.update("DELETE FROM t_agent_log WHERE agent_id=?",agent);f.jdbc.update("UPDATE t_agent_log_state SET retained_rows=retained_rows-?,retained_bytes=retained_bytes-? WHERE id=1",usage.get("rows"),usage.get("bytes"));});
        f.jdbc.update("DELETE FROM t_audit_log WHERE uid=?",f.actor);f.close();}}
    LogLine line(String value){return LogLine.newBuilder().setTs(System.currentTimeMillis()).setContent(value).putFields("timestamp_kind","observed").build();}
    void batch(String id,String source,LogLine... lines){f.tx.executeWithoutResult(s->intake.onBatch(agent,id,RptLogBatch.newBuilder().setSource(source).addAllLines(List.of(lines)).build()));}
    void add(String value){batch(UUID.randomUUID().toString(),"auth.log",line(value));}
    LogSearchService.Query query(String keyword,String cursor){return new LogSearchService.Query(from,to,agent,"",keyword,cursor);}
    @SuppressWarnings("unchecked") List<Map<String,Object>> items(Map<String,Object> value){return (List<Map<String,Object>>)value.get("items");}
    Map<String,Object> find(String key){return search.search(query(key,null),f.actor);}
    String first(){return items(find("")).getFirst().get("id").toString();}
    long count(){return f.jdbc.queryForObject("SELECT COUNT(*) FROM t_agent_log WHERE agent_id=?",Long.class,agent);}
    @Test void fullUnicodeRawTextAndMetadataSurviveCompatibilityPreviewAndReplay(){
        String raw="  客户\t"+"🙂".repeat(3000)+"\n<script>alert(1)</script>";var line=line(raw).toBuilder().putFields("source_event_id","a".repeat(64)).build();
        batch("r1","auth.log",line);batch("r2","auth.log",line);assertEquals(1,count());var detail=search.detail(first(),f.actor);
        assertEquals(raw,detail.get("content"));assertEquals(LogBatchService.sha(raw),detail.get("content_sha256"));assertEquals(true,detail.get("raw_available"));assertEquals("observed",detail.get("time_kind"));assertNotNull(detail.get("receivedAt"));
        assertTrue(f.jdbc.queryForObject("SELECT LENGTH(content) FROM t_agent_log WHERE agent_id=?",Integer.class,agent)<=4000);
        assertThrows(IllegalArgumentException.class,()->batch("r3","auth.log",line.toBuilder().setContent("changed").build()));assertEquals(raw,search.detail(first(),f.actor).get("content"));
    }
    @Test void reportIdentityDeduplicatesLegacyLinesAndDifferentAgentOrSourceRemainsDistinct(){
        batch("same-report","auth.log",line("first"),line("first"));batch("same-report","auth.log",line("first"),line("first"));assertEquals(2,count());
        batch("same-report","secure",line("first"));assertEquals(3,count());
    }
    @Test void oversizedOrInvalidLateLineRollsBackEntireBatchAndCapacityAccounting(){
        var before=f.jdbc.queryForMap("SELECT * FROM t_agent_log_state WHERE id=1");
        assertThrows(IllegalArgumentException.class,()->batch("invalid","auth.log",line("would be accepted"),line("x".repeat(65537))));assertEquals(0,count());assertEquals(before,f.jdbc.queryForMap("SELECT * FROM t_agent_log_state WHERE id=1"));
        assertThrows(IllegalArgumentException.class,()->batch("fields","auth.log",line("valid"),line("bad").toBuilder().putFields("field","x".repeat(4097)).build()));
        var tooMany=new LogLine[101];Arrays.fill(tooMany,line("row"));assertThrows(IllegalArgumentException.class,()->batch("many","auth.log",tooMany));
        assertThrows(IllegalArgumentException.class,()->batch("nul","auth.log",line("x\u0000y")));assertEquals(0,count());
    }
    @Test void lateIdentityConflictRollsBackEarlierInsert(){
        var known=line("known").toBuilder().putFields("source_event_id","b".repeat(64)).build();batch("one","secure",known);
        assertThrows(IllegalArgumentException.class,()->batch("two","secure",line("new"),known.toBuilder().setContent("tampered").build()));assertEquals(1,count());
    }
    @Test void percentUnderscoreQuotesAndSqlAreLiteralAndSearchIsCaseSensitive(){
        add("100%_客户 ' OR 1=1 --");add("100xx客户");add("CASE");
        assertEquals(1,items(find("%_")).size());assertEquals(1,items(find("' OR 1=1 --")).size());assertEquals(0,items(find("case")).size());assertEquals(1,items(find("CASE")).size());
    }
    @Test void receivedTimeUsesInclusiveStartAndExclusiveEndWithSqliteSecondPrecisionDefaults(){
        long start=System.currentTimeMillis()/1000*1000-60000;
        add("before");String before=first();add("at start");String at=first();add("at end");String end=first();
        f.jdbc.update("UPDATE t_agent_log SET created_at=? WHERE id=?",f.dialect.timestamp(Instant.ofEpochMilli(start-1)),Long.parseLong(before));
        f.jdbc.update("UPDATE t_agent_log SET created_at=? WHERE id=?",f.dialect.isSqlite()?Instant.ofEpochMilli(start).toString().replace("T"," ").replace("Z",""):f.dialect.timestamp(Instant.ofEpochMilli(start)),Long.parseLong(at));
        f.jdbc.update("UPDATE t_agent_log SET created_at=? WHERE id=?",f.dialect.timestamp(Instant.ofEpochMilli(start+1000)),Long.parseLong(end));
        var rows=items(search.search(new LogSearchService.Query(start,start+1000,agent,"","",null),f.actor));assertEquals(1,rows.size());assertEquals(at,rows.getFirst().get("id"));
    }
    @Test void frozenCursorExcludesLaterInsertsAndRejectsDifferentFilterOrMalformedInput(){
        var lines=new LogLine[60];for(int i=0;i<60;i++)lines[i]=line("same "+i);batch("page","auth.log",lines);
        var first=find("same");assertEquals(50,items(first).size());String cursor=(String)first.get("nextCursor");assertNotNull(cursor);
        add("same inserted later");var second=search.search(query("same",cursor),f.actor);assertEquals(10,items(second).size());assertEquals(true,second.get("scanComplete"));
        Set<Object> ids=new HashSet<>();for(var r:items(first))ids.add(r.get("id"));for(var r:items(second))assertTrue(ids.add(r.get("id")));assertEquals(60,ids.size());
        assertThrows(IllegalArgumentException.class,()->search.search(query("different",cursor),f.actor));assertThrows(IllegalArgumentException.class,()->search.search(query("same","invalid"),f.actor));
    }
    @Test void emptyScanCanHaveContinuationAndDoesNotClaimGlobalNoMatches(){
        add("older target");long older=Long.parseLong(first());f.jdbc.update("INSERT INTO t_agent_log(id,agent_id,source,content,log_ts) VALUES (?,?,'fixture','recent',0)",older+6000,agent);
        // This deliberately imported legacy row is outside intake accounting until teardown.
        f.jdbc.update("UPDATE t_agent_log_state SET retained_rows=retained_rows+1 WHERE id=1");
        var page=find("target");assertTrue(items(page).isEmpty());assertEquals(false,page.get("scanComplete"));var next=search.search(query("target",(String)page.get("nextCursor")),f.actor);assertEquals(1,items(next).size());
    }
    @Test void currentRoleAndDisabledAccountBlockSearchDetailAndExport(){
        add("private");String id=first();for(String role:List.of("viewer","operator")){
            f.jdbc.update("UPDATE t_user SET role_id=(SELECT id FROM t_role WHERE name=?) WHERE id=?",role,f.actor);
            assertThrows(IllegalArgumentException.class,()->find(""));assertThrows(IllegalArgumentException.class,()->search.detail(id,f.actor));assertThrows(IllegalArgumentException.class,()->search.export(new LogSearchService.Export(List.of(id),"ndjson"),f.actor));
        }f.jdbc.update("UPDATE t_user SET role_id=1,status=0 WHERE id=?",f.actor);assertThrows(IllegalArgumentException.class,()->find(""));assertThrows(IllegalArgumentException.class,()->search.detail(id,f.actor));
    }
    @Test void capacityRejectionIsAtomicAndSmallRetentionCleanupReleasesCharges(){
        add("expires");var baseline=f.jdbc.queryForMap("SELECT * FROM t_agent_log_state WHERE id=1");
        try{f.jdbc.update("UPDATE t_agent_log_state SET retained_rows=? WHERE id=1",LogBatchService.MAX_ROWS);assertThrows(IllegalArgumentException.class,()->add("over cap"));assertEquals(1,count());}
        finally{f.jdbc.update("UPDATE t_agent_log_state SET retained_rows=? WHERE id=1",baseline.get("retained_rows"));}
        f.jdbc.update("UPDATE t_agent_log SET created_at=? WHERE agent_id=?",f.dialect.timestamp(Instant.now().minus(Duration.ofDays(40))),agent);
        f.tx.executeWithoutResult(s->assertEquals(1,intake.cleanupBefore(f.dialect.timestamp(Instant.now().minus(Duration.ofDays(30))))));assertEquals(0,count());
        var after=f.jdbc.queryForMap("SELECT * FROM t_agent_log_state WHERE id=1");assertEquals(((Number)baseline.get("retained_rows")).longValue()-1,((Number)after.get("retained_rows")).longValue());assertTrue(((Number)after.get("retained_bytes")).longValue()<((Number)baseline.get("retained_bytes")).longValue());
    }
    @Test void boundedExportsPreserveTextNeutralizeCsvAndAuditOnlySuccessfulDownloads(){
        String raw=" \t=HYPERLINK(\"https://invalid\",\"客户\")\n<script>unsafe()</script>";add(raw);String id=first();
        var json=search.export(new LogSearchService.Export(List.of(id),"ndjson"),f.actor);assertEquals(LogBatchService.sha(new String(json.bytes(),StandardCharsets.UTF_8)),json.sha256());assertEquals(raw,JsonUtils.read(new String(json.bytes(),StandardCharsets.UTF_8)).path("content").asText());
        var csv=search.export(new LogSearchService.Export(List.of(id),"csv"),f.actor);assertTrue(new String(csv.bytes(),StandardCharsets.UTF_8).contains("\"' \t=HYPERLINK(\"\"https://invalid"));
        assertEquals(2,f.jdbc.queryForObject("SELECT COUNT(*) FROM t_audit_log WHERE uid=? AND path='/api/logs/export'",Integer.class,f.actor));
        assertThrows(IllegalArgumentException.class,()->search.export(new LogSearchService.Export(List.of(id,id),"csv"),f.actor));assertThrows(IllegalArgumentException.class,()->search.export(new LogSearchService.Export(List.of("9223372036854775807"),"csv"),f.actor));
        f.jdbc.update("UPDATE t_agent_log SET raw_content='tampered' WHERE id=?",Long.parseLong(id));assertThrows(IllegalStateException.class,()->search.detail(id,f.actor));assertThrows(IllegalStateException.class,()->search.export(new LogSearchService.Export(List.of(id),"csv"),f.actor));
    }
    @Test void captureActualRestSearchDetailExportsAndAuthorityForProductionBrowser()throws Exception {
        add(" \t=HYPERLINK(\"https://invalid\",\"客户\")\n  用户 auth%_\n<img src=x onerror=window.logXss=true>\n=SUM(1,2)");batch("windows","windows-security",line("<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><EventID>4625</EventID></System></Event>").toBuilder().putFields("timestamp_kind","event").putFields("format","windows_event_xml").build());
        batch("status","auth.log",line("Log collection status: rotation_gap_possible").toBuilder().putFields("record_kind","collection_status").build());
        batch("prefix","auth.log",line("retained raw prefix").toBuilder().putFields("truncated","true").putFields("original_bytes","90000").build());
        var holder=mock(JwtSecretHolder.class);String secret="raw-log-rest-capture-secret-".repeat(4);when(holder.secret()).thenReturn(secret);
        MockMvc mvc=MockMvcBuilders.standaloneSetup(new LogController(search)).setControllerAdvice(new RestExceptionHandler()).addInterceptors(new JwtAuthInterceptor(holder)).build();
        String token="Bearer "+JwtUtil.sign(secret,Map.of("uid",f.actor,"username","fixture","role","admin"),3600);
        var response=mvc.perform(get("/api/logs").param("from",""+from).param("to",""+to).param("agent",agent).header("Authorization",token)).andReturn().getResponse();
        assertEquals(200,response.getStatus());assertEquals("no-store",response.getHeader("Cache-Control"));var body=JsonUtils.read(response.getContentAsString(StandardCharsets.UTF_8));assertEquals(4,body.path("data").path("items").size());
        String id="";var details=new LinkedHashMap<String,Object>();var exportIds=new ArrayList<String>();for(var row:body.path("data").path("items")){String key=row.path("id").asText();exportIds.add(key);details.put(key,search.detail(key,f.actor));if(row.path("preview").asText().contains("onerror"))id=key;}assertFalse(id.isEmpty());var detail=mvc.perform(get("/api/logs/"+id).header("Authorization",token)).andReturn().getResponse();assertEquals(200,detail.getStatus());
        String folder=System.getenv("ALINKSEC_LOG_SEARCH_FIXTURES");if(folder==null)folder="../.tmp/log-search-fixtures";Path target=Path.of(folder).toAbsolutePath();Files.createDirectories(target);String db=f.dialect.isSqlite()?"sqlite":"postgres";
        var rawDetail=JsonUtils.read(detail.getContentAsString(StandardCharsets.UTF_8)).path("data");assertEquals(search.detail(id,f.actor).get("content"),rawDetail.path("content").asText());assertTrue(rawDetail.path("content").asText().contains("客户"));
        var captured=new LinkedHashMap<String,Object>();captured.put("database",db);captured.put("agent",agent);captured.put("search",body.path("data"));captured.put("detail",rawDetail);captured.put("empty",find("absent-keyword"));captured.put("details",details);captured.put("literal",find("%_"));
        for(String format:List.of("csv","ndjson")){
            String request=JsonUtils.write(new LogSearchService.Export(exportIds,format));var file=mvc.perform(post("/api/logs/export").header("Authorization",token).contentType("application/json").content(request)).andReturn().getResponse();assertEquals(200,file.getStatus());assertEquals("sandbox; default-src 'none'",file.getHeader("Content-Security-Policy"));assertEquals(com.alinksec.service.evidence.EvidenceService.sha(file.getContentAsByteArray()),file.getHeader("X-Content-SHA256"));Files.write(target.resolve("logs-"+db+"."+format),file.getContentAsByteArray());captured.put(format+"Sha256",file.getHeader("X-Content-SHA256"));
        }
        var pageLines=new LogLine[60];for(int n=0;n<60;n++)pageLines[n]=line("paging "+n);batch("browser-pages","auth.log",pageLines);var page1=find("paging");var page2=search.search(query("paging",(String)page1.get("nextCursor")),f.actor);captured.put("paging",Map.of("first",page1,"second",page2));
        assertEquals(401,mvc.perform(get("/api/logs")).andReturn().getResponse().getStatus());
        for(String role:List.of("viewer","operator")){String auth="Bearer "+JwtUtil.sign(secret,Map.of("uid",f.actor,"username","fixture","role",role),3600);assertEquals(403,mvc.perform(get("/api/logs").header("Authorization",auth)).andReturn().getResponse().getStatus());}
        f.jdbc.update("UPDATE t_user SET status=0 WHERE id=?",f.actor);assertEquals(400,mvc.perform(get("/api/logs").param("from",""+from).param("to",""+to).header("Authorization",token)).andReturn().getResponse().getStatus());
        captured.put("authority",Map.of("unauthenticated",401,"viewer",403,"operator",403,"disabledCurrentAdmin",400));Files.writeString(target.resolve("console-"+db+".json"),JsonUtils.write(captured));
    }
}
