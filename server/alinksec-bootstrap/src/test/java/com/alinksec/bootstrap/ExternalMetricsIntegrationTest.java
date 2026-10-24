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
            long first=(Instant.now().minusSeconds(10).toEpochMilli()/1000)*1000+123,second=first+1111;
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
                assertEquals(200,instant.getStatus());JsonNode result=JsonUtils.read(instant.getContentAsString()).path("data");
                assertEquals("success",result.path("status").asText());assertEquals(1,result.path("data").path("result").size());
                assertEquals("25.75",result.path("data").path("result").get(0).path("value").get(1).asText());
                var range=mvc.perform(get("/api/metrics/query_range").param("query",query).param("start",Long.toString(first/1000))
                        .param("end",time).param("step","1s")).andReturn().getResponse();
                assertEquals(200,range.getStatus());assertFalse(JsonUtils.read(range.getContentAsString()).path("data").path("data").path("result").isEmpty());
                Path evidence=Path.of(System.getenv("ALINKSEC_EXTERNAL_EVIDENCE")).resolve("metrics");Files.createDirectories(evidence);
                Files.writeString(evidence.resolve("export.ndjson"),exported);
                Files.write(evidence.resolve("query.json"),instant.getContentAsByteArray());Files.write(evidence.resolve("query-range.json"),range.getContentAsByteArray());
                Files.writeString(evidence.resolve("result.json"),JsonUtils.write(Map.of("accepted",true,"sampleCount",2,"timestamps",List.of(first,second),
                        "millisecondPrecisionVerified",true,"escapedLabelsVerified",true,"productionForwarder",true,"productionQueryClient",true,
                        "nativeAgentTransportVerified",false,"realHostLongSoakVerified",false))+"\n");
            } finally {Locale.setDefault(previous);forwarder.stop();}
        }
    }
}
