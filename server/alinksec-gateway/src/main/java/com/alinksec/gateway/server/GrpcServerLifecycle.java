package com.alinksec.gateway.server;

import com.alinksec.gateway.rpc.AgentAuthInterceptor;
import com.alinksec.gateway.rpc.AgentChannelImpl;
import com.alinksec.gateway.rpc.EnrollServiceImpl;
import com.alinksec.service.cert.CertService;
import com.alinksec.service.config.AlinkSecProperties;
import io.grpc.Server;
import io.grpc.ServerInterceptors;
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.netty.shaded.io.netty.handler.ssl.ClientAuth;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslContextBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.SmartLifecycle;
import org.springframework.stereotype.Component;

import java.io.File;

/**
 * gRPC 服务器（mTLS，设计文档 §6）：
 * - 服务端证书：CertService 首启生成（SAN 覆盖配置接入地址）；
 * - 客户端信任：平台 CA 签发的 Agent 证书；
 * - 生命周期跟随 Spring 容器。
 */
@Component
public class GrpcServerLifecycle implements SmartLifecycle {

    private static final Logger log = LoggerFactory.getLogger(GrpcServerLifecycle.class);

    private final AlinkSecProperties props;
    private final CertService certService;
    private final AgentAuthInterceptor authInterceptor;
    private final EnrollServiceImpl enrollService;
    private final AgentChannelImpl agentChannel;

    private Server server;
    private volatile boolean running;

    public GrpcServerLifecycle(AlinkSecProperties props, CertService certService,
                                AgentAuthInterceptor authInterceptor,
                                EnrollServiceImpl enrollService, AgentChannelImpl agentChannel) {
        this.props = props;
        this.certService = certService;
        this.authInterceptor = authInterceptor;
        this.enrollService = enrollService;
        this.agentChannel = agentChannel;
    }

    @Override
    public void start() {
        try {
            File caFile = new File(props.getServer().getCertDir(), "ca.crt");
            SslContextBuilder sslBuilder = SslContextBuilder.forServer(
                    certService.serverCertFile(), certService.serverKeyFile());
            // 客户端证书校验：平台 CA 签发 + 强制提供（Enroll 走 token，注册后才有证书，
            // 因此 Enroll 需要单独的宽松端口/拦截器放行 —— M1 将 Enroll 暴露在同一端口但由
            // Agent 侧 InsecureSkipVerify + token 认证，服务端 REQUIRE 会拒绝无证书的 Enroll，
            // 故这里使用 OPTIONAL：有证书则校验，无证书放行（Enroll），业务层由拦截器兜底。
            sslBuilder.trustManager(caFile).clientAuth(ClientAuth.OPTIONAL);

            server = NettyServerBuilder.forPort(props.getServer().getPort())
                    .sslContext(GrpcSslContexts.configure(sslBuilder).build())
                    .addService(ServerInterceptors.intercept(enrollService, authInterceptor))
                    .addService(ServerInterceptors.intercept(agentChannel, authInterceptor))
                    .build()
                    .start();
            running = true;
            log.info("gRPC 服务已启动: port={} (mTLS)", props.getServer().getPort());
        } catch (Exception e) {
            throw new IllegalStateException("gRPC 服务器启动失败", e);
        }
    }

    @Override
    public void stop() {
        if (server != null) {
            server.shutdown();
            try {
                if (!server.awaitTermination(10, java.util.concurrent.TimeUnit.SECONDS)) {
                    server.shutdownNow();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                server.shutdownNow();
            }
            log.info("gRPC 服务已停止");
        }
        running = false;
    }

    @Override
    public boolean isRunning() {
        return running;
    }
}
