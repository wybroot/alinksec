package com.alinksec.service.metrics;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.config.AlinkSecProperties;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * VictoriaMetrics 查询客户端：/api/v1/query、/api/v1/query_range。
 * 返回 VM 原生 JSON 结构（status/data/result），前端直接消费。
 */
@Component
public class VmQueryClient {

    private final AlinkSecProperties props;
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3)).build();

    public VmQueryClient(AlinkSecProperties props) {
        this.props = props;
    }

    public Object query(String query, String time) {
        StringBuilder url = new StringBuilder(props.getMetrics().getVmBaseUrl())
                .append("/api/v1/query?query=").append(enc(query));
        if (time != null && !time.isBlank()) {
            url.append("&time=").append(enc(time));
        }
        return getForJson(url.toString());
    }

    public Object queryRange(String query, String start, String end, String step) {
        String url = props.getMetrics().getVmBaseUrl() + "/api/v1/query_range"
                + "?query=" + enc(query)
                + "&start=" + enc(start)
                + "&end=" + enc(end)
                + "&step=" + enc(step);
        return getForJson(url);
    }

    private Object getForJson(String url) {
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(10))
                    .GET()
                    .build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                throw new IllegalStateException("VM 查询失败 HTTP " + resp.statusCode());
            }
            return JsonUtils.read(resp.body());
        } catch (IOException e) {
            throw new IllegalStateException("VM 查询不可达: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("VM 查询中断", e);
        }
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}
