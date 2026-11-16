package com.alinksec.service.metrics;

import com.alinksec.proto.MetricSample;
import com.alinksec.proto.RptMetricsBatch;
import com.alinksec.service.config.AlinkSecProperties;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import jakarta.annotation.PreDestroy;
import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Pattern;

/** Bounded, lossy metrics export. Business reports never wait for the downstream. */
@Service
public class MetricsForwarder {
    static final int MAX_RECORDS=4096, MAX_BYTES=8*1024*1024, MAX_LINE=8192, MAX_BODY=256*1024;
    private static final Pattern NAME=Pattern.compile("[a-zA-Z_:][a-zA-Z0-9_:]{0,199}"), LABEL=Pattern.compile("[a-zA-Z_][a-zA-Z0-9_]{0,99}");
    private final AlinkSecProperties props;
    private final JdbcTemplate jdbc;
    private final HttpClient http=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
    private final ArrayDeque<byte[]> buffer=new ArrayDeque<>();
    private record Hostname(String value,long expires){}
    private final LinkedHashMap<String,Hostname> hostnames=new LinkedHashMap<>(16,.75f,true);
    private int bytes;
    private long dropped, rejected, failed;
    private final ScheduledExecutorService flusher=Executors.newSingleThreadScheduledExecutor(r->{var t=new Thread(r,"vm-metrics-flusher");t.setDaemon(true);return t;});
    @org.springframework.beans.factory.annotation.Autowired
    public MetricsForwarder(AlinkSecProperties props,JdbcTemplate jdbc) {this(props,jdbc,true);}
    MetricsForwarder(AlinkSecProperties props,JdbcTemplate jdbc,boolean start) {
        this.props=props;this.jdbc=jdbc;
        if(start)flusher.scheduleWithFixedDelay(this::flush,100,100,TimeUnit.MILLISECONDS);
    }
    public void onBatch(String agentId,RptMetricsBatch batch) {
        if(!props.getMetrics().isEnabled())return;
        String hostname=hostnameOf(agentId);
        for(var sample:batch.getSamplesList()) {
            byte[] line=formatLine(sample,agentId,hostname);
            synchronized(buffer) {
                if(line==null){rejected++;continue;}
                while(buffer.size()>=MAX_RECORDS || bytes+line.length>MAX_BYTES){bytes-=buffer.removeFirst().length;dropped++;}
                buffer.addLast(line);bytes+=line.length;
            }
        }
    }
    private String hostnameOf(String agentId) {
        long now=System.nanoTime();
        synchronized(hostnames){var cached=hostnames.get(agentId);if(cached!=null && cached.expires()>now)return cached.value();}
        String hostname=agentId;
        try {var names=jdbc.query("SELECT hostname FROM t_agent WHERE agent_id=? LIMIT 1",(rs,i)->rs.getString(1),agentId);if(!names.isEmpty())hostname=names.get(0);}catch(RuntimeException ignored){}
        if(hostname==null || hostname.length()>256)hostname=agentId;
        synchronized(hostnames){while(hostnames.size()>=4096)hostnames.remove(hostnames.keySet().iterator().next());hostnames.put(agentId,new Hostname(hostname,now+TimeUnit.MINUTES.toNanos(1)));}
        return hostname;
    }
    static byte[] formatLine(MetricSample s,String agentId,String hostname) {
        if(!NAME.matcher(s.getName()).matches() || s.getLabelsCount()>32 || !Double.isFinite(s.getValue()) || s.getTs()<0 || agentId==null || agentId.length()>256 || hostname==null || hostname.length()>256 || invalidControl(agentId) || invalidControl(hostname))return null;
        StringBuilder b=new StringBuilder(s.getName()).append("{agent_id=\"").append(escape(agentId)).append("\",hostname=\"").append(escape(hostname)).append('"');
        for(var e:s.getLabelsMap().entrySet()) {
            if(!LABEL.matcher(e.getKey()).matches() || e.getKey().startsWith("__") || Set.of("agent_id","hostname").contains(e.getKey()) || e.getValue().length()>1024 || invalidControl(e.getValue()))return null;
            b.append(',').append(e.getKey()).append("=\"").append(escape(e.getValue())).append('"');
            if(b.length()>MAX_LINE)return null;
        }
        b.append("} ").append(s.getValue()).append(' ').append(s.getTs()).append('\n');
        byte[] line=b.toString().getBytes(StandardCharsets.UTF_8);
        return line.length>MAX_LINE?null:line;
    }
    private static boolean invalidControl(String value){return value.chars().anyMatch(c->Character.isISOControl(c) && c!='\n');}
    private static String escape(String s){return s.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n");}
    public Map<String,Long> statistics(){synchronized(buffer){return Map.of("records",(long)buffer.size(),"bytes",(long)bytes,"dropped",dropped,"rejected",rejected,"failed",failed);}}
    void flush() {
        byte[] body;
        synchronized(buffer) {
            var out=new java.io.ByteArrayOutputStream(MAX_BODY);
            while(!buffer.isEmpty() && out.size()+buffer.peekFirst().length<=MAX_BODY){var line=buffer.removeFirst();bytes-=line.length;out.writeBytes(line);}
            if(out.size()==0)return;
            body=out.toByteArray();
        }
        try {
            var request=HttpRequest.newBuilder(URI.create(props.getMetrics().getVmBaseUrl()+"/api/v1/import/prometheus")).timeout(Duration.ofSeconds(5)).header("Content-Type","text/plain; charset=utf-8").POST(HttpRequest.BodyPublishers.ofByteArray(body)).build();
            int status=http.send(request,HttpResponse.BodyHandlers.discarding()).statusCode();
            if(status!=200 && status!=204){synchronized(buffer){failed++;}}
        }catch(Exception e){synchronized(buffer){failed++;}if(e instanceof InterruptedException)Thread.currentThread().interrupt();}
    }
    @PreDestroy public void stop(){flusher.shutdownNow();}
}
