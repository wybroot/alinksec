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
                    try { deliveryWorker.execute(() -> {
                        try { deliveryTransaction.executeWithoutResult(status -> send(agentId, cmd)); }
                        catch (RuntimeException e) { log.warn("已提交指令保留待重推: cmd_id={} agent={}", cmd.getCmdId(), agentId); }
                    }); }
                    catch (RuntimeException e) { log.warn("已提交指令保留待重推: cmd_id={} agent={}", cmd.getCmdId(), agentId); }
                }
            });
        } else { send(agentId, cmd); }
        return cmd.getCmdId();
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

    private void send(String agentId, Command cmd) {
        String cmdId = cmd.getCmdId();
        if (sender.send(agentId, cmd)) {
            repository.markSent(cmdId);
            log.debug("指令已下发: cmd_id={} agent={} type={}", cmdId, agentId, commandType(cmd));
        } else {
            log.info("指令挂起待推: cmd_id={} agent={} type={}", cmdId, agentId, commandType(cmd));
        }
    }

    /** 策略版本同步指令（心跳版本不一致时由 HeartbeatService / 规则编辑后触发）；policyJson 为空 = 仅版本同步（M1 兼容） */
    public void dispatchPolicySync(String agentId, String policyVersion, String policyJson) {
        dispatch(agentId, Command.newBuilder()
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
        for (Map<String, Object> row : repository.findPendingByAgent(agentId)) {
            Command command;
            try {
                command = refreshDownloadCredentials(agentId, rebuild(row));
            } catch (IllegalStateException e) {
                String cmdId = (String) row.get("cmd_id");
                if (repository.markFailed(cmdId, e.getMessage()) > 0) {
                    notifyTerminal(agentId, cmdId, CommandLifecycleListener.TerminalState.FAILED,
                            e.getMessage());
                }
                log.error("Cannot deliver pending command: cmd_id={}", cmdId, e);
                continue;
            }
            if (!sender.send(agentId, command)) {
                return;
            }
            repository.markSent((String) row.get("cmd_id"));
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
                if (repository.markTimeout(cmdId) > 0) {
                    notifyTerminal(agentId, cmdId, CommandLifecycleListener.TerminalState.TIMEOUT,
                            "指令 ACK 超时");
                    log.warn("指令超时: cmd_id={} agent={} retry={}", cmdId, agentId, retry);
                }
                continue;
            }
            repository.findByCmdId(cmdId).ifPresent(cmdRow -> {
                // 仅在 Agent 在线时重推；离线则等心跳触发（M2 待推队列）
                Command command;
                try {
                    command = refreshDownloadCredentials(agentId, rebuild(cmdRow));
                } catch (IllegalStateException e) {
                    if (repository.markFailed(cmdId, e.getMessage()) > 0) {
                        notifyTerminal(agentId, cmdId, CommandLifecycleListener.TerminalState.FAILED,
                                e.getMessage());
                    }
                    log.error("Cannot rebuild command for retry: cmd_id={}", cmdId, e);
                    return;
                }
                if (sender.send(agentId, command)) {
                    repository.bumpRetry(cmdId);
                    log.info("指令重推: cmd_id={} agent={} retry={}", cmdId, agentId, retry + 1);
                }
            });
        }
    }

    private Command rebuild(Map<String, Object> row) {
        String payloadJson = String.valueOf(row.get("payload"));
        String encoded = com.alinksec.common.util.JsonUtils.read(payloadJson)
                .path("command_b64").asText();
        if (encoded.isBlank()) {
            throw new IllegalStateException("command payload does not contain a serialized command");
        }
        try {
            return Command.parseFrom(Base64.getDecoder().decode(encoded));
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
            case VULN_FIX -> refreshPatchDownloadCredentials(agentId, command);
            default -> command;
        };
    }

    private Command refreshPatchDownloadCredentials(String agentId, Command command) {
        CmdVulnFix.Builder fix = command.getVulnFix().toBuilder().clearFixes();
        for (FixItem item : command.getVulnFix().getFixesList()) {
            if (item.getType() != FixItem.FixType.PACKAGE) {
                fix.addFixes(item);
                continue;
            }
            Map<String, Object> payload;
            try {
                payload = com.alinksec.common.util.JsonUtils.read(item.getPayload(), Map.class);
            } catch (Exception e) {
                throw new IllegalStateException("cannot read patch payload", e);
            }
            if (payload == null || !(payload.get("download_url") instanceof String downloadUrl)) {
                throw new IllegalStateException("patch payload has no download_url");
            }
            payload = new java.util.LinkedHashMap<>(payload);
            payload.put("download_url", refreshDownloadUrl(agentId, downloadUrl, "patch", "filename"));
            fix.addFixes(item.toBuilder().setPayload(com.alinksec.common.util.JsonUtils.write(payload)));
        }
        return command.toBuilder().setVulnFix(fix).build();
    }

    private String refreshDownloadUrl(String agentId, String url, String resourceType, String resourceParameter) {
        try {
            URI uri = URI.create(url);
            String resourceKey = UriComponentsBuilder.fromUri(uri).build().getQueryParams().getFirst(resourceParameter);
            if (resourceKey == null || resourceKey.isBlank()) {
                throw new IllegalStateException("download URL has no " + resourceParameter);
            }
            return UriComponentsBuilder.fromUriString(downloadBaseUrl(resourceType))
                    .path(uri.getPath())
                    .replaceQueryParam(resourceParameter, resourceKey)
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
