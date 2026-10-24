package com.alinksec.gateway.rpc;

import com.alinksec.proto.AgentChannelGrpc;
import com.alinksec.proto.Command;
import com.alinksec.proto.Report;
import com.alinksec.service.agent.AgentEntity;
import com.alinksec.service.agent.AgentRepository;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.report.ReportDispatcher;
import com.alinksec.service.protect.IsolationLeaseService;
import com.alinksec.proto.CmdIsolationConfirm;
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
    private final CommandService commandService;
    private final IsolationLeaseService isolationLeases;
    @org.springframework.beans.factory.annotation.Autowired(required=false)
    private com.alinksec.service.cluster.ClusterReportIngress reportIngress;

    public AgentChannelImpl(ReportDispatcher dispatcher, AgentRepository agentRepository,
                             com.alinksec.gateway.channel.ConnectionRegistry registry,
                             CommandService commandService, IsolationLeaseService isolationLeases) {
        this.dispatcher = dispatcher;
        this.agentRepository = agentRepository;
        this.registry = registry;
        this.commandService = commandService;
        this.isolationLeases = isolationLeases;
    }

    @Override
    public StreamObserver<Report> channel(StreamObserver<Command> responseObserver) {
        return new StreamObserver<>() {
            volatile String authenticatedAgentId;
            volatile boolean authenticated;
            volatile boolean closed;

            @Override
            public void onNext(Report report) {
                if (closed) {
                    return;
                }
                try {
                    if (!authenticate(report)) {
                        closed = true;
                        if (authenticatedAgentId != null) {
                            registry.unregister(authenticatedAgentId, responseObserver);
                        }
                        responseObserver.onError(Status.PERMISSION_DENIED
                                .withDescription("agent_id 与证书不匹配").asRuntimeException());
                        return;
                    }
                    registry.withCurrent(authenticatedAgentId,responseObserver,()-> {
                        var current=agentRepository.findByAgentId(authenticatedAgentId);
                        if(current.isEmpty() || current.get().status()==AgentEntity.STATUS_DISABLED
                                || current.get().status()==AgentEntity.STATUS_DELETED)
                            throw new SecurityException("agent_disabled_or_deleted");
                        if (report.hasHeartbeat()) {
                            registry.weakPasswordContract(authenticatedAgentId,responseObserver,report.getHeartbeat().getWeakPasswordContract());
                            registry.upgradeContract(authenticatedAgentId,responseObserver,report.getHeartbeat().getUpgradeContract());
                            registry.isolationContract(authenticatedAgentId,responseObserver,report.getHeartbeat().getIsolationContract());
                        }
                        if (report.hasIsolationState()) {
                            if(registry.isolationCapable(authenticatedAgentId,responseObserver)
                                    && isolationLeases.observe(authenticatedAgentId,report.getIsolationState())) {
                                var pulse=report.getIsolationState();
                                registry.sendCurrent(authenticatedAgentId,responseObserver,Command.newBuilder().setIsolationConfirm(CmdIsolationConfirm.newBuilder()
                                        .setLeaseId(pulse.getLeaseId()).setNonce(pulse.getNonce())).build());
                            }
                        } else {
                            if(reportIngress==null || !reportIngress.admit(authenticatedAgentId,report))
                                dispatcher.dispatch(authenticatedAgentId, report);
                            if(report.hasHeartbeat()) registry.heartbeatReady(authenticatedAgentId,responseObserver);
                            if(report.hasEvidence()) dispatcher.evidenceReceipt(authenticatedAgentId,report).ifPresent(receipt->
                                    registry.sendCurrent(authenticatedAgentId,responseObserver,Command.newBuilder().setEvidenceReceipt(receipt).build()));
                            if(report.hasFixResult()) {
                                var receipts=dispatcher.windowsUpdateReceipts(authenticatedAgentId,report.getFixResult());
                                if(!receipts.isEmpty()) registry.sendCurrent(authenticatedAgentId,responseObserver,Command.newBuilder().setWindowsUpdateReceipt(com.alinksec.proto.CmdWindowsUpdateReceipt.newBuilder().addAllRecords(receipts)).build());
                            }
                            // dispatch returns only after its alert + receipt transaction commits.
                            if(com.alinksec.service.protect.WindowsLoginService.outcome(report)) {
                                String id=report.getReportId();
                                if(!id.matches("[0-9a-f]{64}-windows-login"))throw new IllegalArgumentException("invalid login receipt");
                                registry.sendCurrent(authenticatedAgentId,responseObserver,Command.newBuilder()
                                        .setWindowsLoginReceipt(com.alinksec.proto.CmdWindowsLoginReceipt.newBuilder().addEventIds(id.substring(0,64))).build());
                            }
                        }
                    });
                } catch (SecurityException | com.alinksec.service.cluster.ClusterUnavailable failure) {
                    closed=true;
                    if(authenticatedAgentId!=null) registry.unregister(authenticatedAgentId,responseObserver);
                    var status=failure instanceof SecurityException ? Status.PERMISSION_DENIED : Status.UNAVAILABLE;
                    responseObserver.onError(status.withDescription("agent session is unavailable").asRuntimeException());
                } catch (Exception e) {
                    log.error("Report 处理异常: agent={} err={}", report.getAgentId(), e.getMessage(), e);
                    // 单条处理失败不拆流（Agent 无需重发：非关键路径靠下轮心跳/快照补偿）
                }
            }

            /** 首条 Report 完成认证：证书 CN = agent_id，且主机未禁用 */
            private boolean authenticate(Report report) {
                if (authenticated) {
                    if (!authenticatedAgentId.equals(report.getAgentId())) {
                        log.warn("流内身份校验失败: authenticated_agent={} report_agent={}",
                                authenticatedAgentId, report.getAgentId());
                        return false;
                    }
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
                registry.register(report.getAgentId(), responseObserver);
                authenticatedAgentId = report.getAgentId();
                authenticated = true;
                // Capability belongs to this authenticated connection. A
                // previous, newer Agent may have been downgraded while offline.
                registry.withCurrent(authenticatedAgentId,responseObserver,()-> {
                agentRepository.weakPasswordContract(authenticatedAgentId, report.hasHeartbeat()?report.getHeartbeat().getWeakPasswordContract():0);
                agentRepository.windowsUpdateContract(authenticatedAgentId,report.hasHeartbeat()?report.getHeartbeat().getWindowsUpdateContract():0);
                agentRepository.evidenceContract(authenticatedAgentId,report.hasHeartbeat()?report.getHeartbeat().getEvidenceContract():0);
                agentRepository.upgradeContract(authenticatedAgentId,
                        report.hasHeartbeat() ? report.getHeartbeat().getUpgradeContract() : 0);
                agentRepository.isolationContract(authenticatedAgentId,
                        report.hasHeartbeat() ? report.getHeartbeat().getIsolationContract() : 0);
                if (report.hasHeartbeat()) registry.upgradeContract(authenticatedAgentId,responseObserver,
                        report.getHeartbeat().getUpgradeContract());
                if (report.hasHeartbeat()) registry.isolationContract(authenticatedAgentId,responseObserver,
                        report.getHeartbeat().getIsolationContract());
                if (report.hasHeartbeat()) registry.weakPasswordContract(authenticatedAgentId,responseObserver,report.getHeartbeat().getWeakPasswordContract());
                });
                if(!registry.deferredDelivery()) commandService.deliverPending(authenticatedAgentId);
                return true;
            }

            @Override
            public void onError(Throwable t) {
                closed = true;
                if (authenticatedAgentId != null) {
                    registry.unregister(authenticatedAgentId, responseObserver);
                }
                log.info("Agent 流异常断开: agent={} err={}", authenticatedAgentId, t.getMessage());
            }

            @Override
            public void onCompleted() {
                if (closed) {
                    return;
                }
                closed = true;
                if (authenticatedAgentId != null) {
                    registry.unregister(authenticatedAgentId, responseObserver);
                }
                responseObserver.onCompleted();
            }
        };
    }
}
