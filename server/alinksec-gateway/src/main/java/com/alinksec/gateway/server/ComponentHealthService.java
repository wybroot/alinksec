package com.alinksec.gateway.server;

import com.alinksec.gateway.channel.ConnectionRegistry;
import com.alinksec.service.cluster.*;
import com.alinksec.service.config.AlinkSecProperties;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.lang.management.ManagementFactory;
import java.net.URI;
import java.net.http.*;
import java.nio.file.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.function.Supplier;

/** Read-only diagnostics of this server instance; credentials and exception text never leave it. */
@Service
public class ComponentHealthService {
    private final JdbcTemplate jdbc;
    private final AlinkSecProperties app;
    private final ClusterProperties clusterProperties;
    private final ClusterRuntime cluster;
    private final RedisLeases redis;
    private final RabbitTransport rabbit;
    private final GrpcServerLifecycle grpc;
    private final ConnectionRegistry connections;
    private final HttpClient http=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2))
            .followRedirects(HttpClient.Redirect.NEVER).build();
    private long cachedAt;
    private Map<String,Object> cached;

    public ComponentHealthService(JdbcTemplate jdbc, AlinkSecProperties app, ClusterProperties clusterProperties,
            ClusterRuntime cluster, RedisLeases redis, RabbitTransport rabbit, GrpcServerLifecycle grpc, ConnectionRegistry connections) {
        this.jdbc=jdbc;this.app=app;this.clusterProperties=clusterProperties;this.cluster=cluster;
        this.redis=redis;this.rabbit=rabbit;this.grpc=grpc;this.connections=connections;
    }

    public synchronized Map<String,Object> snapshot() {
        long now=System.currentTimeMillis();
        if (cached!=null && now-cachedAt<10_000) return cached;
        var components=new ArrayList<Map<String,Object>>();
        components.add(probe("api","服务端 API",()->state("healthy","请求处理正常",Map.of(
                "uptimeSeconds",ManagementFactory.getRuntimeMXBean().getUptime()/1000,
                "heapUsedBytes",ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed(),
                "heapMaxBytes",ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getMax()))));
        components.add(probe("database","关系数据库",()-> {
            if (!Integer.valueOf(1).equals(jdbc.queryForObject("SELECT 1",Integer.class))) throw new IllegalStateException();
            return state("healthy","连接与只读查询正常",Map.of("type",app.getDatabase().getType()));
        }));
        components.add(probe("grpc","Agent 通信服务",()->state(grpc.isRunning()?"healthy":"down",
                grpc.isRunning()?"mTLS 通信服务运行中":"通信服务未运行",Map.of("localConnections",connections.onlineCount()))));
        components.add(probe("storage","文件存储",this::storage));
        components.add(probe("tls","服务端证书",this::certificate));
        components.add(app.getMetrics().isEnabled()?probe("metrics","VictoriaMetrics",this::metrics):disabled("metrics","VictoriaMetrics","未启用长期指标存储；主机基础性能可使用心跳采样"));
        components.add(clusterProperties.isEnabled()?probe("redis","Redis",()->state(redis.healthy()?"healthy":"down","集群租约连接检测",Map.of())):disabled("redis","Redis","当前为单机模式"));
        components.add(clusterProperties.isEnabled()?probe("rabbitmq","RabbitMQ",()->state(rabbit.healthy()?"healthy":"down","报告队列检测",Map.of())):disabled("rabbitmq","RabbitMQ","当前为单机模式"));
        components.add(probe("cluster","运行模式",()->state(cluster.ready()?"healthy":"down",
                clusterProperties.isEnabled()?"集群就绪状态":"单机运行",Map.of("mode",clusterProperties.isEnabled()?"cluster":"single"))));
        String overall=components.stream().anyMatch(c->"down".equals(c.get("status")))?"down":
                components.stream().anyMatch(c->"degraded".equals(c.get("status")))?"degraded":"healthy";
        cached=Map.of("checkedAt",Instant.now().toString(),"status",overall,"components",components,"cacheSeconds",10,
                "scope","当前服务端实例");
        cachedAt=System.currentTimeMillis();
        return cached;
    }

    private Map<String,Object> metrics() {
        try {
            String base=app.getMetrics().getVmBaseUrl().replaceAll("/+$","");
            var request=HttpRequest.newBuilder(URI.create(base+"/health")).timeout(Duration.ofSeconds(2)).GET().build();
            int status=http.send(request,HttpResponse.BodyHandlers.discarding()).statusCode();
            return state(status==200?"healthy":"down",status==200?"健康接口响应正常":"健康接口响应异常",Map.of());
        } catch(InterruptedException e) { Thread.currentThread().interrupt();throw new IllegalStateException(); }
        catch(Exception e) { throw new IllegalStateException(); }
    }

    private Map<String,Object> storage() {
        long minimum=Long.MAX_VALUE;
        for(String configured:List.of(app.getServer().getCertDir(),app.getServer().getWebTlsDir(),
                app.getSignature().getStorageDir(),app.getPatch().getStorageDir(),app.getUpgrade().getStorageDir())) {
            Path path=Path.of(configured).toAbsolutePath();
            // An unused package directory may not yet exist. Check the nearest
            // existing parent without creating or changing any application file.
            while(path!=null && !Files.exists(path)) path=path.getParent();
            if(path==null || !Files.isDirectory(path) || !Files.isReadable(path) || !Files.isWritable(path)) throw new IllegalStateException();
            try { minimum=Math.min(minimum,Files.getFileStore(path).getUsableSpace()); }
            catch(Exception e) { throw new IllegalStateException(); }
        }
        return state(minimum<512L*1024*1024?"degraded":"healthy",minimum<512L*1024*1024?"可用磁盘空间不足 512 MiB":"存储目录可读写",Map.of("minimumFreeBytes",minimum));
    }

    private Map<String,Object> certificate() {
        try(var input=Files.newInputStream(Path.of(app.getServer().getCertDir(),"server.crt"))) {
            var cert=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(input);
            cert.checkValidity();long days=Duration.between(Instant.now(),cert.getNotAfter().toInstant()).toDays();
            return state(days<30?"degraded":"healthy",days<30?"证书将在 30 天内过期":"证书在有效期内",
                    Map.of("expiresAt",cert.getNotAfter().toInstant().toString(),"remainingDays",days));
        } catch(Exception e) { return state("down","证书不可读取、尚未生效或已过期",Map.of()); }
    }

    private static Map<String,Object> state(String status,String message,Map<String,Object> details) {
        return Map.of("status",status,"message",message,"details",details);
    }
    private static Map<String,Object> disabled(String id,String name,String message) {
        var result=new LinkedHashMap<String,Object>(state("disabled",message,Map.of()));
        result.put("id",id);result.put("name",name);result.put("durationMs",0);return result;
    }
    private static Map<String,Object> probe(String id,String name,Supplier<Map<String,Object>> check) {
        long start=System.nanoTime();Map<String,Object> value;
        try { value=check.get(); } catch(RuntimeException e) { value=state("down","检测失败，请检查组件连接及服务端日志",Map.of()); }
        var result=new LinkedHashMap<String,Object>(value);
        result.put("id",id);result.put("name",name);result.put("durationMs",Duration.ofNanos(System.nanoTime()-start).toMillis());
        return result;
    }
}
