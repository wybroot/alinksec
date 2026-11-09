package com.alinksec.service.metrics;
import com.alinksec.proto.*;
import com.alinksec.service.config.AlinkSecProperties;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.nio.charset.StandardCharsets;

class MetricsForwarderTest {
    @Test void identifiersCannotInjectOrOverrideAnotherAgent(){
        var good=MetricSample.newBuilder().setName("cpu_usage").setValue(1).setTs(1).putLabels("label","quoted\"\\\nvalue").build();
        String line=new String(MetricsForwarder.formatLine(good,"agent-a","host-a"),StandardCharsets.UTF_8);
        assertEquals(1,line.lines().count());assertTrue(line.contains("label=\"quoted\\\"\\\\\\nvalue\""));
        for(String name:new String[]{"cpu\nforeign{agent_id=\"agent-b\"}","cpu{}","cpu value","", "9metric"})assertNull(MetricsForwarder.formatLine(good.toBuilder().setName(name).build(),"a","h"));
        assertNull(MetricsForwarder.formatLine(good.toBuilder().putLabels("label","bad\rvalue").build(),"a","h"));
        for(String key:new String[]{"agent_id","hostname","bad\nkey","__name__"})assertNull(MetricsForwarder.formatLine(good.toBuilder().putLabels(key,"agent-b").build(),"a","h"));
    }
    @Test void concurrentOverloadRemainsBoundedAndRejectsHugeSamples()throws Exception{
        var props=new AlinkSecProperties();props.getMetrics().setEnabled(true);
        var forwarder=new MetricsForwarder(props,mock(JdbcTemplate.class),false);
        try {
            var sample=MetricSample.newBuilder().setName("metric").setValue(1).putLabels("one","a".repeat(1024)).putLabels("two","a".repeat(1024)).putLabels("three","a".repeat(1024)).build();
            var batch=RptMetricsBatch.newBuilder();for(int i=0;i<600;i++)batch.addSamples(sample);
            var threads=new java.util.ArrayList<Thread>();
            for(int i=0;i<4;i++){var thread=new Thread(()->{for(int n=0;n<6;n++)forwarder.onBatch("agent",batch.build());});threads.add(thread);thread.start();}
            for(var thread:threads)thread.join();
            var state=forwarder.statistics();assertTrue(state.get("bytes")<=MetricsForwarder.MAX_BYTES);assertTrue(state.get("records")<=MetricsForwarder.MAX_RECORDS);assertTrue(state.get("dropped")>0);
            forwarder.onBatch("agent",RptMetricsBatch.newBuilder().addSamples(sample.toBuilder().putLabels("huge","a".repeat(100000))).build());assertEquals(1L,forwarder.statistics().get("rejected"));
        }finally{forwarder.stop();}
    }
}
