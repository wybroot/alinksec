package com.alinksec.service.metrics;
import com.alinksec.proto.*;
import com.alinksec.service.config.AlinkSecProperties;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicInteger;
import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;
class MetricsExportIntegrationTest {
 @Test void realHttpExportPreservesAgentLabelsAndBoundsEveryBody()throws Exception{
  var received=new AtomicReference<String>("");var maximum=new AtomicInteger();var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
  server.createContext("/api/v1/import/prometheus",exchange->{var bytes=exchange.getRequestBody().readAllBytes();maximum.accumulateAndGet(bytes.length,Math::max);received.set(new String(bytes,StandardCharsets.UTF_8));exchange.sendResponseHeaders(204,-1);exchange.close();});server.start();
  var props=new AlinkSecProperties();props.getMetrics().setEnabled(true);props.getMetrics().setVmBaseUrl("http://127.0.0.1:"+server.getAddress().getPort());
  var exporter=new MetricsForwarder(props,mock(JdbcTemplate.class),false);
  try {
   var sample=MetricSample.newBuilder().setName("cpu_usage").setValue(1).setTs(1).build();
   exporter.onBatch("agent-a",RptMetricsBatch.newBuilder().addSamples(sample).addSamples(sample.toBuilder().setName("cpu\nforeign{agent_id=\"agent-b\"} 1")).addSamples(sample.toBuilder().putLabels("agent_id","agent-b")).build());
   exporter.flush();assertEquals(1,received.get().lines().count());assertTrue(received.get().contains("agent_id=\"agent-a\""));assertFalse(received.get().contains("agent-b"));
   exporter.onBatch("agent-b",RptMetricsBatch.newBuilder().addSamples(sample).build());exporter.flush();assertTrue(received.get().contains("agent_id=\"agent-b\""));assertEquals(2L,exporter.statistics().get("rejected"));
   var batch=RptMetricsBatch.newBuilder();for(int i=0;i<1000;i++)batch.addSamples(sample.toBuilder().putLabels("payload","a".repeat(1000)));
   exporter.onBatch("agent-a",batch.build());while(exporter.statistics().get("records")>0)exporter.flush();assertTrue(maximum.get()<=MetricsForwarder.MAX_BODY);assertEquals(0L,exporter.statistics().get("failed"));
  }finally{exporter.stop();server.stop(0);}
 }
}
