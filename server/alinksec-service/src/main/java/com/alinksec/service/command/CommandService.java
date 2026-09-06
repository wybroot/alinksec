package com.alinksec.service.command;

import com.alinksec.proto.Command;
import com.alinksec.proto.CmdPolicySync;
import com.alinksec.proto.CmdVulnFix;
import com.alinksec.proto.FixItem;
import com.alinksec.proto.RptAck;
import com.alinksec.service.download.AgentDownloadTokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.Base64;

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

    public CommandService(CommandRepository repository, CommandSender sender,
                          AgentDownloadTokenService downloadTokens) {
        this.repository = repository;
        this.sender = sender;
        this.downloadTokens = downloadTokens;
    }

    /**
     * 下发指令。Agent 不在线 → 保持 PENDING（M2 接入 Redis 待推队列后由 gateway 消费补推）。
     */
    public void dispatch(String agentId, Command.Builder command, Long issuedBy) {
        String cmdId = UUID.randomUUID().toString();
        Command cmd = command.setCmdId(cmdId)
                .setIssuedAt(System.currentTimeMillis())
                .build();
        repository.insert(cmdId, agentId, commandType(cmd),
                com.alinksec.common.util.JsonUtils.write(payloadOf(cmd)), issuedBy);
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
    public void onAck(RptAck ack) {
        if (ack.getCmdId().isBlank()) {
            return;
        }
        int rows = repository.onAck(ack);
        if (rows == 0) {
            log.debug("ACK 未命中指令行（终态后重复 ACK）: cmd_id={}", ack.getCmdId());
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
                repository.markFailed(cmdId, e.getMessage());
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
                repository.markTimeout(cmdId);
                log.warn("指令超时: cmd_id={} agent={} retry={}", cmdId, agentId, retry);
                continue;
            }
            repository.findByCmdId(cmdId).ifPresent(cmdRow -> {
                // 仅在 Agent 在线时重推；离线则等心跳触发（M2 待推队列）
                Command command;
                try {
                    command = refreshDownloadCredentials(agentId, rebuild(cmdRow));
                } catch (IllegalStateException e) {
                    repository.markFailed(cmdId, e.getMessage());
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
            return UriComponentsBuilder.fromUri(uri)
                    .replaceQueryParam("token", downloadTokens.issue(agentId, resourceType, resourceKey))
                    .build(true)
                    .toUriString();
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("invalid download URL", e);
        }
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
}
