package com.alinksec.service.command;

import com.alinksec.proto.Command;
import com.alinksec.proto.CmdPolicySync;
import com.alinksec.proto.CmdVulnFix;
import com.alinksec.proto.FixItem;
import com.alinksec.proto.RptAck;
import com.alinksec.service.download.AgentDownloadTokenService;
import com.alinksec.service.config.AlinkSecProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.Base64;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import jakarta.annotation.PreDestroy;

/**
 * 指令编排（通信协议 §3.1）：
 * 入库 PENDING → 在线则写入 stream 并置 SENT；
 * 30s 未 RECEIVED → 重推（≤3 次）→ 仍无响应置 TIMEOUT。
 */
@Service
public class CommandService {

    private static final Logger log = LoggerFactory.getLogger(CommandService.class);

    private final CommandRepository repository;
    private final CommandSender sender;
    private final AgentDownloadTokenService downloadTokens;
    private final AlinkSecProperties props;
    private final List<CommandLifecycleListener> lifecycleListeners;
    private final TransactionTemplate deliveryTransaction;
    private final ThreadPoolExecutor deliveryWorker = new ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS,
            new ArrayBlockingQueue<>(500), runnable -> {
                Thread thread = new Thread(runnable, "command-delivery"); thread.setDaemon(true); return thread;
            });

    public CommandService(CommandRepository repository, CommandSender sender,
                          AgentDownloadTokenService downloadTokens, AlinkSecProperties props,
                          List<CommandLifecycleListener> lifecycleListeners,
                          PlatformTransactionManager transactionManager) {
        this.repository = repository;
        this.sender = sender;
        this.downloadTokens = downloadTokens;
        this.props = props;
        this.lifecycleListeners = lifecycleListeners;
        this.deliveryTransaction = new TransactionTemplate(transactionManager);
        this.deliveryTransaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    /**
     * 下发指令。Agent 不在线 → 保持 PENDING（M2 接入 Redis 待推队列后由 gateway 消费补推）。
     */
    @Transactional
    public String dispatch(String agentId, Command.Builder command, Long issuedBy) {
        if(sender.deferredDelivery()) return dispatchAfterCommit(agentId,command,issuedBy);
        Command cmd = persist(agentId, command, issuedBy);
        send(agentId, cmd);
        return cmd.getCmdId();
    }

    /** Durable queue in the task transaction; expose it to the Agent only after snapshots commit. */
    @Transactional
    public String dispatchAfterCommit(String agentId, Command.Builder command, Long issuedBy) {
        Command cmd = persist(agentId, command, issuedBy);
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override public void afterCommit() {
                    // Transaction resources are still bound during afterCommit. In SQLite
                    // IMMEDIATE mode even the committed connection holds the next write
                    // transaction until cleanup. A separate worker lets cleanup finish,
                    // and also supports deployments with a single pooled connection.
                    enqueueDelivery(agentId,cmd);
                }
            });
        } else if(sender.deferredDelivery()) { enqueueDelivery(agentId,cmd); }
        else { send(agentId, cmd); }
        return cmd.getCmdId();
    }

    private void enqueueDelivery(String agentId,Command command) {
        try { deliveryWorker.execute(()-> {
            try {
                deliverInIdentity(agentId,()->deliveryTransaction.execute(status->send(agentId,command)));
            } catch(RuntimeException failure) {
                log.warn("已提交指令保留待重推: cmd_id={} agent={}",command.getCmdId(),agentId);
            }
        }); } catch(RuntimeException failure) {
            log.warn("已提交指令保留待重推: cmd_id={} agent={}",command.getCmdId(),agentId);
        }
    }

    private Boolean deliverInIdentity(String agentId,java.util.function.Supplier<Boolean> action) {
        return sender.deferredDelivery() ? sender.withIdentity(agentId,action,false) : action.get();
    }

    @PreDestroy public void close() { deliveryWorker.shutdownNow(); }

    private Command persist(String agentId, Command.Builder command, Long issuedBy) {
        String cmdId = UUID.randomUUID().toString();
        Command cmd = command.setCmdId(cmdId)
                .setIssuedAt(System.currentTimeMillis())
                .build();
        repository.insert(cmdId, agentId, commandType(cmd),
                com.alinksec.common.util.JsonUtils.write(payloadOf(cmd)), issuedBy);
        lifecycleListeners.forEach(listener -> listener.onDispatched(agentId, cmd));
        return cmd;
    }

    private boolean send(String agentId, Command cmd) { return send(agentId,cmd,null); }

    private boolean send(String agentId,Command cmd,Integer retry) {
        String cmdId = cmd.getCmdId();
        try {
            for (var listener:lifecycleListeners) cmd=listener.prepareDelivery(agentId,cmd);
        } catch (IllegalArgumentException | IllegalStateException e) {
            if (repository.markFailed(cmdId,e.getMessage())>0) notifyTerminal(agentId,cmdId,CommandLifecycleListener.TerminalState.FAILED,e.getMessage());
            log.warn("指令执行条件失效，停止派发: cmd={} reason={}",cmdId,e.getMessage());
            return true;
        }
        if (repository.lockForDelivery(cmdId,retry==null ? CommandRepository.ST_PENDING : CommandRepository.ST_SENT,retry)!=1) return true;
        if (sender.send(agentId, cmd)) {
            if (retry==null) repository.markSent(cmdId); else repository.bumpRetry(cmdId);
            log.debug("指令已下发: cmd_id={} agent={} type={}", cmdId, agentId, commandType(cmd));
            return true;
        } else {
            log.info("指令挂起待推: cmd_id={} agent={} type={}", cmdId, agentId, commandType(cmd));
            return false;
        }
    }

    /** 策略版本同步指令（心跳版本不一致时由 HeartbeatService / 规则编辑后触发）；policyJson 为空 = 仅版本同步（M1 兼容） */
    public void dispatchPolicySync(String agentId, String policyVersion, String policyJson) {
        dispatchAfterCommit(agentId, Command.newBuilder()
                .setPolicySync(CmdPolicySync.newBuilder()
                        .setPolicyVersion(policyVersion)
                        .setPolicyJson(policyJson == null ? "" : policyJson)), null);
    }

    /** Agent ACK 状态机推进 */
    @Transactional
    public void onAck(String agentId, RptAck ack) {
        if (ack.getCmdId().isBlank()) {
            return;
        }
        lifecycleListeners.forEach(listener -> listener.beforeAck(agentId,ack.getCmdId()));
        int rows = repository.onAck(agentId, ack);
        if (rows == 0) {
            log.debug("ACK 未命中指令行（终态后重复 ACK）: cmd_id={}", ack.getCmdId());
            return;
        }
        if (ack.getStage() == RptAck.Stage.DONE) {
            notifyTerminal(agentId, ack.getCmdId(), CommandLifecycleListener.TerminalState.DONE,
                    ack.getMessage());
        } else if (ack.getStage() == RptAck.Stage.FAILED) {
            notifyTerminal(agentId, ack.getCmdId(), CommandLifecycleListener.TerminalState.FAILED,
                    ack.getMessage());
        }
    }

    /** Called after a newly authenticated Agent stream is registered. */
    public void deliverPending(String agentId) {
        var pending=sender.deferredDelivery() ? repository.findPendingByAgent(agentId,100) : repository.findPendingByAgent(agentId);
        for (Map<String, Object> row : pending) {
            Command command;
            try {
                command = refreshDownloadCredentials(agentId, rebuild(row));
            } catch (IllegalStateException e) {
                String cmdId = (String) row.get("cmd_id");
                failDelivery(agentId,cmdId,e.getMessage());
                log.error("Cannot deliver pending command: cmd_id={}", cmdId, e);
                continue;
            }
            Command ready=command;
            if (!Boolean.TRUE.equals(deliverInIdentity(agentId,()->deliveryTransaction.execute(status -> send(agentId,ready))))) {
                return;
            }
        }
    }

    /** SENT 超时扫描：10s 一次；重推或置 TIMEOUT */
    @Scheduled(fixedDelay = 10_000, initialDelay = 30_000)
    public void sweepTimeout() {
        List<Map<String, Object>> timedOut = repository.findAckTimedout();
        for (Map<String, Object> row : timedOut) {
            String cmdId = (String) row.get("cmd_id");
            String agentId = (String) row.get("agent_id");
            int retry = ((Number) row.get("retry_count")).intValue();
            if (retry >= CommandRepository.MAX_RETRY) {
                deliveryTransaction.executeWithoutResult(status -> {
                    lifecycleListeners.forEach(listener -> listener.beforeAck(agentId,cmdId));
                    if (repository.markTimeout(cmdId)>0) notifyTerminal(agentId,cmdId,CommandLifecycleListener.TerminalState.TIMEOUT,"指令 ACK 超时");
                });
                continue;
            }
            repository.findByCmdId(cmdId).ifPresent(cmdRow -> {
                // 仅在 Agent 在线时重推；离线则等心跳触发（M2 待推队列）
                Command command;
                try {
                    command = refreshDownloadCredentials(agentId, rebuild(cmdRow));
                } catch (IllegalStateException e) {
                    failDelivery(agentId,cmdId,e.getMessage());
                    log.error("Cannot rebuild command for retry: cmd_id={}", cmdId, e);
                    return;
                }
                Command ready=command;
                deliverInIdentity(agentId,()->deliveryTransaction.execute(status -> send(agentId,ready,retry)));
            });
        }
    }

    private void failDelivery(String agentId,String cmdId,String reason) {
        deliveryTransaction.executeWithoutResult(status -> {
            lifecycleListeners.forEach(listener -> listener.beforeAck(agentId,cmdId));
            if (repository.markFailed(cmdId,reason)>0) notifyTerminal(agentId,cmdId,CommandLifecycleListener.TerminalState.FAILED,reason);
        });
    }

    private Command rebuild(Map<String, Object> row) {
        String payloadJson = String.valueOf(row.get("payload"));
        String encoded = com.alinksec.common.util.JsonUtils.read(payloadJson)
                .path("command_b64").asText();
        if (encoded.isBlank()) {
            throw new IllegalStateException("command payload does not contain a serialized command");
        }
        try {
            Command command=Command.parseFrom(Base64.getDecoder().decode(encoded));
            String id=String.valueOf(row.get("cmd_id"));
            if (!command.getCmdId().isBlank() && !id.equals(command.getCmdId()))
                throw new IllegalStateException("serialized command identity differs from its durable row");
            return command.toBuilder().setCmdId(id).build();
        } catch (Exception e) {
            throw new IllegalStateException("cannot rebuild command " + row.get("cmd_id"), e);
        }
    }

    /** Reissue short-lived package credentials when a command is replayed. */
    private Command refreshDownloadCredentials(String agentId, Command command) {
        return switch (command.getPayloadCase()) {
            case AGENT_UPGRADE -> command.toBuilder().setAgentUpgrade(command.getAgentUpgrade().toBuilder()
                    .setDownloadUrl(refreshDownloadUrl(agentId, command.getAgentUpgrade().getDownloadUrl(),
                            "agent-upgrade", "packageKey"))).build();
            case SIGNATURE_UPDATE -> command.toBuilder().setSignatureUpdate(command.getSignatureUpdate().toBuilder()
                    .setDownloadUrl(refreshDownloadUrl(agentId, command.getSignatureUpdate().getDownloadUrl(),
                            "virus-db", "packageKey"))).build();
            // PACKAGE URLs are reissued by the task-bound guard after validating
            // current approval, window, inventory, rule and immutable review.
            case VULN_FIX -> command;
            default -> command;
        };
    }

    private String refreshDownloadUrl(String agentId, String url, String resourceType, String resourceParameter) {
        try {
            URI uri = URI.create(url);
            String resourceKey = UriComponentsBuilder.fromUri(uri).build().getQueryParams().getFirst(resourceParameter);
            if (resourceKey == null || resourceKey.isBlank()) {
                throw new IllegalStateException("download URL has no " + resourceParameter);
            }
            // Query values are still encoded here. Bind fresh credentials to
            // the original key, then encode once for the replayed HTTP query.
            resourceKey = URLDecoder.decode(resourceKey, StandardCharsets.UTF_8);
            return UriComponentsBuilder.fromUriString(downloadBaseUrl(resourceType))
                    .path(uri.getPath())
                    .replaceQueryParam(resourceParameter, URLEncoder.encode(resourceKey, StandardCharsets.UTF_8))
                    .replaceQueryParam("token", downloadTokens.issue(agentId, resourceType, resourceKey))
                    .build(true)
                    .toUriString();
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("invalid download URL", e);
        }
    }

    private String downloadBaseUrl(String resourceType) {
        return switch (resourceType) {
            case "agent-upgrade" -> props.getUpgrade().getDownloadBaseUrl();
            case "virus-db" -> props.getSignature().getDownloadBaseUrl();
            case "patch" -> props.getPatch().getDownloadBaseUrl();
            default -> throw new IllegalArgumentException("unknown download resource type: " + resourceType);
        };
    }

    private String commandType(Command cmd) {
        return switch (cmd.getPayloadCase()) {
            case BASELINE_CHECK -> "baseline_check";
            case SCAP_SCAN -> "scap_scan";
            case EVIDENCE_COLLECT -> "evidence_collect";
            case VULN_SCAN -> "vuln_scan";
            case POLICY_SYNC -> "policy_sync";
            case PROTECT_ACTION -> "protect_action";
            case AGENT_UPGRADE -> "agent_upgrade";
            case COLLECT_NOW -> "collect_now";
            case AGENT_CONTROL -> "agent_control";
            case VIRUS_SCAN -> "virus_scan";
            case VIRUS_ACTION -> "virus_action";
            case SIGNATURE_UPDATE -> "signature_update";
            case VULN_FIX -> "vuln_fix";
            case WINDOWS_UPDATE_SCAN -> "windows_update_scan";
            default -> "unknown";
        };
    }

    private Map<String, Object> payloadOf(Command cmd) {
        return Map.of("command_b64", Base64.getEncoder().encodeToString(cmd.toByteArray()));
    }

    private void notifyTerminal(String agentId, String cmdId,
                                CommandLifecycleListener.TerminalState state, String message) {
        lifecycleListeners.forEach(listener -> listener.onTerminal(agentId, cmdId, state, message));
    }
}
