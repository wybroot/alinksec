package com.alinksec.service.metrics;

import com.alinksec.proto.MetricSample;
import com.alinksec.proto.RptMetricsBatch;
import com.alinksec.service.config.AlinkSecProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import jakarta.annotation.PreDestroy;

/**
 * 指标出口（docs/03 §3.2）：RptMetricsBatch → Prometheus 文本格式 →
 * POST {vm}/api/v1/import/prometheus。批量刷写：500 条或 100ms。
 *
 * 统一注入 label：agent_id（必需）+ hostname（冗余，便于直查）。
 * 指标为可再生数据：VM 不可达时整批丢弃并告警日志，不重试不落盘。
 */
@Service
public class MetricsForwarder {

    private static final Logger log = LoggerFactory.getLogger(MetricsForwarder.class);
    private static final int FLUSH_BATCH = 500;

    private final AlinkSecProperties props;
    private final JdbcTemplate jdbc;
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3)).build();
    private final ConcurrentLinkedQueue<String> buffer = new ConcurrentLinkedQueue<>();
    private final Map<String, String> hostnameCache = new ConcurrentHashMap<>();
    private final ScheduledExecutorService flusher = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "vm-metrics-flusher");
        t.setDaemon(true);
        return t;
    });

    public MetricsForwarder(AlinkSecProperties props, JdbcTemplate jdbc) {
        this.props = props;
        this.jdbc = jdbc;
        flusher.scheduleWithFixedDelay(this::flush, 100, 100, TimeUnit.MILLISECONDS);
    }

    public void onBatch(String agentId, RptMetricsBatch batch) {
        if (!props.getMetrics().isEnabled()) {
            return;
        }
        String hostname = hostnameOf(agentId);
        StringBuilder sb = new StringBuilder();
        for (MetricSample s : batch.getSamplesList()) {
            formatLine(sb, s, agentId, hostname);
            sb.append('\n');
            if (sb.length() > 64 * 1024) { // 单次入缓冲上限 64KB，防大包堆积
                buffer.offer(sb.toString());
                sb.setLength(0);
            }
        }
        if (!sb.isEmpty()) {
            buffer.offer(sb.toString());
        }
        if (buffer.size() > 1000) { // 积压上限（VM 长期不可达）：丢最旧
            buffer.poll();
        }
    }

    private void flush() {
        if (buffer.isEmpty()) {
            return;
        }
        StringBuilder body = new StringBuilder();
        int n = 0;
        while (n < FLUSH_BATCH) {
            String chunk = buffer.poll();
            if (chunk == null) {
                break;
            }
            body.append(chunk);
            n++;
        }
        if (body.isEmpty()) {
            return;
        }
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(props.getMetrics().getVmBaseUrl() + "/api/v1/import/prometheus"))
                    .timeout(Duration.ofSeconds(5))
                    .header("Content-Type", "text/plain")
                    .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                    .build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 204 && resp.statusCode() != 200) {
                log.warn("VM 写入非预期状态: {} body={}", resp.statusCode(),
                        resp.body() == null ? "" : resp.body().substring(0, Math.min(200, resp.body().length())));
            }
        } catch (IOException e) {
            log.warn("VM 写入失败（本批丢弃）: {}", e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** 单行：name{agent_id="..",hostname="..",mount=".."} value tsSeconds */
    private void formatLine(StringBuilder sb, MetricSample s, String agentId, String hostname) {
        sb.append(s.getName()).append("{agent_id=\"").append(escape(agentId))
                .append("\",hostname=\"").append(escape(hostname)).append('"');
        for (Map.Entry<String, String> e : s.getLabelsMap().entrySet()) {
            sb.append(',').append(e.getKey()).append("=\"").append(escape(e.getValue())).append('"');
        }
        sb.append("} ").append(s.getValue())
                .append(' ').append(String.format("%.3f", s.getTs() / 1000.0));
    }

    private static String escape(String v) {
        return v == null ? "" : v.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }

    /** hostname 查询缓存（t_agent 快照；缺失返回 agent_id 兜底） */
    private String hostnameOf(String agentId) {
        return hostnameCache.computeIfAbsent(agentId, id -> {
            try {
                List<String> names = jdbc.query(
                        "SELECT hostname FROM t_agent WHERE agent_id = ? LIMIT 1",
                        (rs, i) -> rs.getString(1), id);
                return names.isEmpty() ? id : names.get(0);
            } catch (Exception e) {
                return id;
            }
        });
    }

    @PreDestroy
    public void stop() {
        flusher.shutdownNow();
    }
}
