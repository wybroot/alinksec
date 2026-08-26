package com.alinksec.gateway.rpc;

import com.alinksec.common.error.ApiException;
import com.alinksec.proto.AgentChannelGrpc;
import com.alinksec.proto.Command;
import com.alinksec.proto.Report;
import com.alinksec.service.agent.AgentEntity;
import com.alinksec.service.agent.AgentRepository;
import com.alinksec.service.report.ReportDispatcher;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 主通道：Agent 发起的双向流。
 * 身份来源 = mTLS 证书 CN（由拦截器解析，见 AgentAuthInterceptor），与 Report.agent_id 强校验。
 */
@Service
public class AgentChannelImpl extends AgentChannelGrpc.AgentChannelImplBase {

    private static final Logger log = LoggerFactory.getLogger(AgentChannelImpl.class);

    private final ReportDispatcher dispatcher;
    private final AgentRepository agentRepository;
    private final com.alinksec.gateway.channel.ConnectionRegistry registry;

    public AgentChannelImpl(ReportDispatcher dispatcher, AgentRepository agentRepository,
                            com.alinksec.gateway.channel.ConnectionRegistry registry) {
        this.dispatcher = dispatcher;
        this.agentRepository = agentRepository;
        this.registry = registry;
    }

    @Override
    public StreamObserver<Report> channel(StreamObserver<Command> responseObserver) {
        return new StreamObserver<>() {
            volatile String authenticatedAgentId;
            volatile boolean authenticated;

            @Override
            public void onNext(Report report) {
                try {
                    if (!authenticate(report)) {
                        responseObserver.onError(Status.PERMISSION_DENIED
                                .withDescription("agent_id 与证书不匹配").asRuntimeException());
                        return;
                    }
                    dispatcher.dispatch(report.getAgentId(), report);
                } catch (Exception e) {
                    log.error("Report 处理异常: agent={} err={}", report.getAgentId(), e.getMessage(), e);
                    // 单条处理失败不拆流（Agent 无需重发：非关键路径靠下轮心跳/快照补偿）
                }
            }

            /** 首条 Report 完成认证：证书 CN = agent_id，且主机未禁用 */
            private boolean authenticate(Report report) {
                if (authenticated) {
                    return true;
                }
                String cn = AgentAuthInterceptor.agentId();
                if (cn == null || !cn.equals(report.getAgentId())) {
                    log.warn("身份校验失败: cert_cn={} report_agent={}", cn, report.getAgentId());
                    return false;
                }
                var agent = agentRepository.findByAgentId(report.getAgentId());
                if (agent.isEmpty()) {
                    log.warn("未知 agent: {}", report.getAgentId());
                    return false;
                }
                if (agent.get().status() == AgentEntity.STATUS_DISABLED
                        || agent.get().status() == AgentEntity.STATUS_DELETED) {
                    log.warn("agent 已禁用，拒绝接入: {}", report.getAgentId());
                    return false;
                }
                authenticatedAgentId = report.getAgentId();
                authenticated = true;
                registry.register(authenticatedAgentId, responseObserver);
                return true;
            }

            @Override
            public void onError(Throwable t) {
                if (authenticatedAgentId != null) {
                    registry.unregister(authenticatedAgentId, responseObserver);
                }
                log.info("Agent 流异常断开: agent={} err={}", authenticatedAgentId, t.getMessage());
            }

            @Override
            public void onCompleted() {
                if (authenticatedAgentId != null) {
                    registry.unregister(authenticatedAgentId, responseObserver);
                }
                responseObserver.onCompleted();
            }
        };
    }
}
