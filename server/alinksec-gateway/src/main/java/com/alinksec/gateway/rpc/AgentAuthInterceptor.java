package com.alinksec.gateway.rpc;

import io.grpc.Context;
import io.grpc.Contexts;
import io.grpc.Grpc;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.Status;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.security.cert.X509Certificate;
import java.util.Optional;

/**
 * 从 mTLS 握手证书中提取 CN（= agent_id）放入 gRPC Context，
 * 供 AgentChannelImpl 做身份强校验。无客户端证书的调用（未注册 Enroll）直接拒绝。
 */
@Component
@Order(10)
public class AgentAuthInterceptor implements ServerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(AgentAuthInterceptor.class);

    public static final Context.Key<String> AGENT_ID_KEY = Context.key("alinksec-agent-id");

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
        // Enroll 用 token 认证，放行
        String fullMethod = call.getMethodDescriptor().getFullMethodName();
        if (fullMethod.endsWith("/EnrollService/Enroll")) {
            return next.startCall(call, headers);
        }
        Optional<String> cn = clientCertCn(call);
        if (cn.isEmpty()) {
            call.close(Status.UNAUTHENTICATED.withDescription("缺少客户端证书"), new Metadata());
            return new ServerCall.Listener<>() {};
        }
        Context ctx = Context.current().withValue(AGENT_ID_KEY, cn.get());
        return Contexts.interceptCall(ctx, call, headers, next);
    }

    /** 当前请求的 agent_id（仅在 gRPC 服务端线程内有效） */
    public static String agentId() {
        return AGENT_ID_KEY.get();
    }

    /** 从 TLS 会话提取对端（客户端）证书 CN */
    private static Optional<String> clientCertCn(ServerCall<?, ?> call) {
        try {
            javax.net.ssl.SSLSession sslSession =
                    call.getAttributes().get(io.grpc.Grpc.TRANSPORT_ATTR_SSL_SESSION);
            if (sslSession == null) {
                return Optional.empty();
            }
            java.security.cert.Certificate[] certs = sslSession.getPeerCertificates();
            if (certs != null && certs.length > 0 && certs[0] instanceof X509Certificate x509) {
                return extractCn(x509);
            }
        } catch (Exception e) {
            log.debug("证书提取失败: {}", e.getMessage());
        }
        return Optional.empty();
    }

    private static Optional<String> extractCn(X509Certificate cert) {
        String dn = cert.getSubjectX500Principal().getName();
        for (String part : dn.split(",")) {
            String[] kv = part.trim().split("=", 2);
            if (kv.length == 2 && "CN".equalsIgnoreCase(kv[0].trim())) {
                return Optional.of(kv[1].trim());
            }
        }
        return Optional.empty();
    }
}
