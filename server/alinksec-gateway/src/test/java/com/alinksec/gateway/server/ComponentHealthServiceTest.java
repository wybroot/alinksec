package com.alinksec.gateway.server;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.gateway.channel.ConnectionRegistry;
import com.alinksec.service.cert.CertService;
import com.alinksec.service.cluster.*;
import com.alinksec.service.config.AlinkSecProperties;
import com.alinksec.service.config.DatabaseDialect;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import java.net.InetSocketAddress;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ComponentHealthServiceTest {
    @TempDir Path root;
    AlinkSecProperties app;
    ClusterProperties mode;
    JdbcTemplate jdbc;
    ClusterRuntime cluster;
    RedisLeases redis;
    RabbitTransport rabbit;
    GrpcServerLifecycle grpc;
    ConnectionRegistry connections;
    @BeforeEach void setup() throws Exception {
        app=new AlinkSecProperties();app.getDatabase().setType("sqlite");app.getMetrics().setEnabled(false);
        app.getServer().setCertDir(root.resolve("certs").toString());app.getServer().setWebTlsDir(root.resolve("tls").toString());
        app.getSignature().setStorageDir(root.resolve("signature").toString());app.getPatch().setStorageDir(root.resolve("patch").toString());app.getUpgrade().setStorageDir(root.resolve("upgrade").toString());
        org.springframework.test.util.ReflectionTestUtils.invokeMethod(new CertService(app),"init");
        mode=new ClusterProperties(new DatabaseDialect(app));jdbc=mock(JdbcTemplate.class);when(jdbc.queryForObject("SELECT 1",Integer.class)).thenReturn(1);
        cluster=mock(ClusterRuntime.class);when(cluster.ready()).thenReturn(true);
        redis=mock(RedisLeases.class);rabbit=mock(RabbitTransport.class);grpc=mock(GrpcServerLifecycle.class);when(grpc.isRunning()).thenReturn(true);
        connections=mock(ConnectionRegistry.class);when(connections.onlineCount()).thenReturn(2);
    }
    ComponentHealthService service() { return new ComponentHealthService(jdbc,app,mode,cluster,redis,rabbit,grpc,connections); }
    @SuppressWarnings("unchecked")
    static Map<String,Object> component(Map<String,Object> snapshot,String id) {
        return ((List<Map<String,Object>>)snapshot.get("components")).stream().filter(row->row.get("id").equals(id)).findFirst().orElseThrow();
    }
    @Test void inactiveDependenciesAreExplicitAndDoNotTriggerConnections() {
        var health=service();var result=health.snapshot();
        assertEquals("healthy",result.get("status"));
        for(String id:List.of("metrics","redis","rabbitmq")) assertEquals("disabled",component(result,id).get("status"));
        verifyNoInteractions(redis,rabbit);
        assertSame(result,health.snapshot());verify(jdbc,times(1)).queryForObject("SELECT 1",Integer.class);
    }
    @Test void actualMetricsHealthStatusIsCheckedAndDatabaseFailuresDoNotLeakSecrets() throws Exception {
        var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        var status=new java.util.concurrent.atomic.AtomicInteger(200);
        server.createContext("/health",exchange->{exchange.sendResponseHeaders(status.get(),-1);exchange.close();});server.start();
        try {
            app.getMetrics().setEnabled(true);app.getMetrics().setVmBaseUrl("http://127.0.0.1:"+server.getAddress().getPort());
            assertEquals("healthy",component(service().snapshot(),"metrics").get("status"));
            status.set(503);
            when(jdbc.queryForObject("SELECT 1",Integer.class)).thenThrow(new IllegalStateException("private-connection-password"));
            var result=service().snapshot();
            assertEquals("down",result.get("status"));assertEquals("down",component(result,"metrics").get("status"));
            assertEquals("down",component(result,"database").get("status"));
            assertFalse(JsonUtils.write(result).contains("private-connection-password"));
        } finally { server.stop(0); }
    }
    @Test void brokenTlsAndStoppedAgentChannelAreShownWithoutHidingOtherComponents() throws Exception {
        Files.writeString(root.resolve("certs/server.crt"),"not a certificate");when(grpc.isRunning()).thenReturn(false);
        mode.setEnabled(true);when(redis.healthy()).thenReturn(false);when(rabbit.healthy()).thenReturn(true);
        var result=service().snapshot();
        assertEquals("down",component(result,"tls").get("status"));assertEquals("down",component(result,"grpc").get("status"));
        assertEquals("down",component(result,"redis").get("status"));assertEquals("healthy",component(result,"rabbitmq").get("status"));
        assertEquals("healthy",component(result,"database").get("status"));
    }
}
