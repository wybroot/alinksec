package com.alinksec.service.metrics;

import com.alinksec.service.config.AlinkSecProperties;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class VmQueryClientTest {
    @Test void bothQueryPathsRequestRecentSamplesAndPreserveEscapedParameters() throws Exception {
        var requests=new ArrayList<Map<String,String>>();
        var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/api/v1/",exchange->{
            var parameters=new HashMap<String,String>();
            parameters.put("path",exchange.getRequestURI().getPath());
            for(String field:exchange.getRequestURI().getRawQuery().split("&")) {
                String[] pair=field.split("=",2);
                parameters.put(URLDecoder.decode(pair[0],StandardCharsets.UTF_8),URLDecoder.decode(pair[1],StandardCharsets.UTF_8));
            }
            requests.add(parameters);
            byte[] body="{\"status\":\"success\",\"data\":{\"result\":[]}}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200,body.length);exchange.getResponseBody().write(body);exchange.close();
        });server.start();
        try {
            var props=new AlinkSecProperties();props.getMetrics().setVmBaseUrl("http://127.0.0.1:"+server.getAddress().getPort());
            var client=new VmQueryClient(props);String expression="sum(rate(cpu{host=\"中文 + &\"}[1m]))";
            assertNotNull(client.query(expression,"1790000000.123"));
            assertNotNull(client.queryRange(expression,"1790000000.123","1790000001.456","100ms"));
            assertEquals(List.of(
                Map.of("path","/api/v1/query","latency_offset","1ms","query",expression,"time","1790000000.123"),
                Map.of("path","/api/v1/query_range","latency_offset","1ms","query",expression,"start","1790000000.123","end","1790000001.456","step","100ms")
            ),requests);
        } finally {server.stop(0);}
    }
}
