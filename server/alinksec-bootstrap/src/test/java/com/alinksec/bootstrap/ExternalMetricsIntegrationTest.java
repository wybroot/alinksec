package com.alinksec.bootstrap;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.gateway.rest.MetricsController;
import com.alinksec.proto.*;
import com.alinksec.service.config.AlinkSecProperties;
import com.alinksec.service.metrics.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.zaxxer.hikari.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/** Real disposable VictoriaMetrics, production exporter/query client and REST response. */
@EnabledIfEnvironmentVariable(named="ALINKSEC_EXTERNAL_EVIDENCE",matches=".+")
class ExternalMetricsIntegrationTest {
    @TempDir Path root;
    @Test @Timeout(30)
    void recentSamplesAreQueryableWithoutTheDefaultThirtySecondOffset() throws Exception {
        String base=System.getenv("ALINKSEC_EXTERNAL_VM_URL");assertNotNull(base);
        var props=new AlinkSecProperties();props.getMetrics().setEnabled(true);props.getMetrics().setVmBaseUrl(base);
        var cfg=new HikariConfig();cfg.setJdbcUrl("jdbc:sqlite:"+root.resolve("recent.db"));cfg.setMaximumPoolSize(1);cfg.setMinimumIdle(1);
        String agent="recent-"+UUID.randomUUID(),metric="alinksec_recent_probe";
        Path evidence=Path.of(System.getenv("ALINKSEC_EXTERNAL_EVIDENCE")).resolve("metrics-recent");Files.createDirectories(evidence);
        try(var pool=new HikariDataSource(cfg)) {
            var jdbc=new JdbcTemplate(pool);jdbc.execute("CREATE TABLE t_agent(agent_id TEXT PRIMARY KEY,hostname TEXT)");jdbc.update("INSERT INTO t_agent VALUES (?, 'Recent sample')",agent);
            var forwarder=new MetricsForwarder(props,jdbc);
            long timestamp=System.currentTimeMillis(),started=System.nanoTime();
            try {
                forwarder.onBatch(agent,RptMetricsBatch.newBuilder().addSamples(MetricSample.newBuilder().setName(metric).setTs(timestamp).setValue(42.125)).build());
                var query=new VmQueryClient(props);String selector=metric+"{agent_id=\""+agent+"\"}";
                var observations=new ArrayList<Map<String,Object>>();JsonNode latest=null;long elapsed=0;
                do {
                    latest=(JsonNode)query.query(selector,null);elapsed=Duration.ofNanos(System.nanoTime()-started).toMillis();
                    observations.add(Map.of("elapsedMillis",elapsed,"response",latest));
                    if(!latest.path("data").path("result").isEmpty())break;
                    Thread.sleep(100);
                }while(elapsed<10_000);
                Files.writeString(evidence.resolve("observations.json"),JsonUtils.write(observations)+"\n");
                assertEquals(1,latest.path("data").path("result").size(),"Production queries must include recent samples without a30s wait");
                assertEquals(42.125,latest.path("data").path("result").get(0).path("value").get(1).asDouble());assertTrue(elapsed<10_000);
                String end=String.format(Locale.ROOT,"%.3f",System.currentTimeMillis()/1000.0);
                JsonNode range=(JsonNode)query.queryRange(selector,Long.toString(timestamp/1000-1),end,"100ms");
                Files.writeString(evidence.resolve("query-range.json"),range.toString()+"\n");
                assertFalse(range.path("data").path("result").isEmpty());
                var client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
                URI export=URI.create(base+"/api/v1/export?match%5B%5D="+URLEncoder.encode(selector,StandardCharsets.UTF_8));
                var raw=client.send(HttpRequest.newBuilder(export).timeout(Duration.ofSeconds(3)).GET().build(),HttpResponse.BodyHandlers.ofString());
                Files.writeString(evidence.resolve("export.ndjson"),raw.body());assertEquals(200,raw.statusCode());
                var sample=JsonUtils.read(raw.body().strip());assertEquals(timestamp,sample.path("timestamps").get(0).asLong());assertEquals(42.125,sample.path("values").get(0).asDouble());
                Files.writeString(evidence.resolve("result.json"),JsonUtils.write(Map.of("accepted",true,"agentId",agent,"timestamp",timestamp,"elapsedMillis",elapsed,
                        "queryLatencyOffset","1ms","realHostLongSoakVerified",false,"oneSecondSlaAccepted",false))+"\n");
            }finally{forwarder.stop();}
        }
    }
    @Test @Timeout(60)
    void realVictoriaMetricsRetainsSampleMillisecondsLabelsAndQueryResults() throws Exception {
        String base=System.getenv("ALINKSEC_EXTERNAL_VM_URL");assertNotNull(base);
        URI uri=URI.create(base);assertEquals("http",uri.getScheme());assertEquals("127.0.0.1",uri.getHost());
        String agent="external-"+UUID.randomUUID(),host="隔离主机\\\"\nVictoriaMetrics";
        var props=new AlinkSecProperties();props.getMetrics().setEnabled(true);props.getMetrics().setVmBaseUrl(base);
        var config=new HikariConfig();config.setJdbcUrl("jdbc:sqlite:"+root.resolve("metrics.db"));config.setMaximumPoolSize(1);config.setMinimumIdle(1);
        try(var pool=new HikariDataSource(config)) {
            var jdbc=new JdbcTemplate(pool);jdbc.execute("CREATE TABLE t_agent(agent_id TEXT PRIMARY KEY,hostname TEXT)");
            jdbc.update("INSERT INTO t_agent VALUES (?,?)",agent,host);
            // The deployed VM defaults to a 30s query latency offset. This checks historical sample
            // fidelity outside that window. Recent visibility is checked separately above.
            long first=(Instant.now().minusSeconds(60).toEpochMilli()/1000)*1000+123,second=first+1111;
            Path evidence=Path.of(System.getenv("ALINKSEC_EXTERNAL_EVIDENCE")).resolve("metrics");Files.createDirectories(evidence);
            String metric="alinksec_external_probe",label="C:\\监测\\\"\n目录";
            var batch=RptMetricsBatch.newBuilder()
                    .addSamples(MetricSample.newBuilder().setName(metric).setTs(first).setValue(12.5).putLabels("mount",label))
                    .addSamples(MetricSample.newBuilder().setName(metric).setTs(second).setValue(25.75).putLabels("mount",label)).build();
            var forwarder=new MetricsForwarder(props,jdbc);
            Locale previous=Locale.getDefault();
            try {
                Locale.setDefault(Locale.GERMANY);forwarder.onBatch(agent,batch);
                var client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
                String selector=metric+"{agent_id=\""+agent+"\"}";
                URI export=URI.create(base+"/api/v1/export?match%5B%5D="+URLEncoder.encode(selector,StandardCharsets.UTF_8));
                String exported="";long deadline=System.nanoTime()+Duration.ofSeconds(25).toNanos();
                while(System.nanoTime()<deadline) {
                    var response=client.send(HttpRequest.newBuilder(export).timeout(Duration.ofSeconds(3)).GET().build(),HttpResponse.BodyHandlers.ofString());
                    assertEquals(200,response.statusCode());exported=response.body();
                    if(!exported.isBlank())break;
                    Thread.sleep(100);
                }
                assertFalse(exported.isBlank(),"Actual samples must be visible at their current millisecond timestamps");
                Files.writeString(evidence.resolve("export.ndjson"),exported);
                var samples=new TreeMap<Long,Double>();
                for(String line:exported.lines().toList()) {
                    JsonNode row=JsonUtils.read(line);assertEquals(agent,row.path("metric").path("agent_id").asText());
                    assertEquals(host,row.path("metric").path("hostname").asText());assertEquals(label,row.path("metric").path("mount").asText());
                    assertEquals(row.path("timestamps").size(),row.path("values").size());
                    for(int n=0;n<row.path("timestamps").size();n++)assertNull(samples.put(row.path("timestamps").get(n).asLong(),row.path("values").get(n).asDouble()));
                }
                assertEquals(Map.of(first,12.5,second,25.75),samples);
                var mvc=MockMvcBuilders.standaloneSetup(new MetricsController(new VmQueryClient(props),props)).build();
                String query="last_over_time("+selector+"[1h])",time=Long.toString(Instant.now().getEpochSecond());
                var instant=mvc.perform(get("/api/metrics/query").param("query",query).param("time",time)).andReturn().getResponse();
                Files.write(evidence.resolve("query.json"),instant.getContentAsByteArray());
                assertEquals(200,instant.getStatus());JsonNode result=JsonUtils.read(instant.getContentAsString()).path("data");
                assertEquals("success",result.path("status").asText());assertEquals(1,result.path("data").path("result").size());
                assertEquals("25.75",result.path("data").path("result").get(0).path("value").get(1).asText());
                var range=mvc.perform(get("/api/metrics/query_range").param("query",query).param("start",Long.toString(first/1000))
                        .param("end",time).param("step","1s")).andReturn().getResponse();
                Files.write(evidence.resolve("query-range.json"),range.getContentAsByteArray());
                assertEquals(200,range.getStatus());assertFalse(JsonUtils.read(range.getContentAsString()).path("data").path("data").path("result").isEmpty());
                Files.writeString(evidence.resolve("result.json"),JsonUtils.write(Map.ofEntries(Map.entry("accepted",true),Map.entry("sampleCount",2),Map.entry("timestamps",List.of(first,second)),
                        Map.entry("millisecondPrecisionVerified",true),Map.entry("escapedLabelsVerified",true),Map.entry("productionForwarder",true),Map.entry("productionQueryClient",true),
                        Map.entry("nativeAgentTransportVerified",false),Map.entry("realHostLongSoakVerified",false),Map.entry("latencyAcceptance",false),Map.entry("sampleAgeSeconds",60)))+"\n");
            } finally {Locale.setDefault(previous);forwarder.stop();}
        }
    }
}
