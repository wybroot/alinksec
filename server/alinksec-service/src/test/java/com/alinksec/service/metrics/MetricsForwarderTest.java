package com.alinksec.service.metrics;

import com.alinksec.proto.*;
import com.alinksec.service.config.AlinkSecProperties;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class MetricsForwarderTest {
    @Test void prometheusTimestampsUseIntegerMillisecondsRegardlessOfDefaultLocale() throws Exception {
        var received=new LinkedBlockingQueue<String>();
        var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/api/v1/import/prometheus",exchange->{
            received.offer(new String(exchange.getRequestBody().readAllBytes(),StandardCharsets.UTF_8));
            exchange.sendResponseHeaders(204,-1);exchange.close();
        });server.start();
        var props=new AlinkSecProperties();props.getMetrics().setEnabled(true);
        props.getMetrics().setVmBaseUrl("http://127.0.0.1:"+server.getAddress().getPort());
        var exporter=new MetricsForwarder(props,mock(JdbcTemplate.class));Locale original=Locale.getDefault();
        try {
            Locale.setDefault(Locale.GERMANY);
            exporter.onBatch("host",RptMetricsBatch.newBuilder().addSamples(MetricSample.newBuilder()
                    .setName("alinksec_cpu_usage").setTs(1_790_000_000_123L).setValue(12.5)).build());
            String body=received.poll(5,TimeUnit.SECONDS);assertNotNull(body);
            String[] fields=body.strip().split(" ");assertEquals(3,fields.length);
            assertEquals(12.5,Double.parseDouble(fields[1]));
            assertEquals("1790000000123",fields[2],"Prometheus exposition timestamps are integer milliseconds, independently of the JVM locale");
        } finally {Locale.setDefault(original);exporter.stop();server.stop(0);}
    }
}
