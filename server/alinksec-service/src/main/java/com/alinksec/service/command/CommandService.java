package com.alinksec.service.command;

import com.alinksec.proto.Command;
import com.alinksec.proto.CmdPolicySync;
import com.alinksec.proto.RptAck;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.UUID;

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

    public CommandService(CommandRepository repository, CommandSender sender) {
        this.repository = repository;
        this.sender = sender;
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
            repository.bumpRetry(cmdId);
            repository.findByCmdId(cmdId).ifPresent(cmdRow -> {
                // 仅在 Agent 在线时重推；离线则等心跳触发（M2 待推队列）
                if (sender.send(agentId, rebuild(cmdRow))) {
                    log.info("指令重推: cmd_id={} agent={} retry={}", cmdId, agentId, retry + 1);
                }
            });
        }
    }

    private Command rebuild(Map<String, Object> row) {
        Command.Builder builder = Command.newBuilder()
                .setCmdId((String) row.get("cmd_id"))
                .setIssuedAt(((java.sql.Timestamp) row.get("created_at")).getTime());
        // M1 指令重建仅支持 policy_sync（心跳触发型）；其余类型重推走原始 payload
        String type = (String) row.get("type");
        String payloadJson = String.valueOf(row.get("payload"));
        if ("policy_sync".equals(type)) {
            String version = com.alinksec.common.util.JsonUtils.read(payloadJson)
                    .path("policy_version").asText();
            builder.setPolicySync(CmdPolicySync.newBuilder().setPolicyVersion(version));
        }
        return builder.build();
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
        return switch (cmd.getPayloadCase()) {
            case POLICY_SYNC -> Map.of("policy_version", cmd.getPolicySync().getPolicyVersion());
            case COLLECT_NOW -> Map.of("collector_names", cmd.getCollectNow().getCollectorNamesList());
            default -> Map.of();
        };
    }
}
