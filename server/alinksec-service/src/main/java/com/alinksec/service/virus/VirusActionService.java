package com.alinksec.service.virus;

import com.alinksec.proto.CmdVirusAction;
import com.alinksec.proto.Command;
import com.alinksec.proto.VirusTarget;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.protect.PolicyStoreService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

/**
 * 病毒处置（docs/05 §1.4）：隔离 / 删除 / 恢复 / 加白。
 *
 * 状态模型（t_virus_finding.status）：0新增 1已隔离 2已删除 3已恢复 4已加白。
 * 乐观更新：先改 finding 状态并下发指令；Agent 执行失败经 ACK FAILED 留痕（指令记录可查），
 * 人工可再次处置或恢复。加白写 t_virus_whitelist 平台全局生效。
 */
@Service
public class VirusActionService {

    private static final Logger log = LoggerFactory.getLogger(VirusActionService.class);

    private final JdbcTemplate jdbc;
    private final CommandService commandService;
    private final PolicyStoreService policyStore;

    public VirusActionService(JdbcTemplate jdbc, CommandService commandService, PolicyStoreService policyStore) {
        this.jdbc = jdbc;
        this.commandService = commandService;
        this.policyStore = policyStore;
    }

    /**
     * 对一组 finding 执行处置。
     * @param action quarantine/delete/restore/whitelist
     * @return 各主机下发情况摘要
     */
    @Transactional
    public Map<String, Object> act(List<Long> findingIds, String action, Long operatedBy) {
        if (findingIds == null || findingIds.isEmpty()) {
            throw new IllegalArgumentException("请选择处置对象");
        }
        String marks = findingIds.stream().map(String::valueOf).reduce((a, b) -> a + "," + b).orElse("");
        List<Map<String, Object>> findings = jdbc.queryForList(
                "SELECT id, agent_id, path, sha256, status FROM t_virus_finding WHERE id IN (" + marks + ")");
        if (findings.isEmpty()) {
            throw new IllegalArgumentException("检出记录不存在");
        }

        switch (action) {
            case "quarantine" -> doAction(findings, CmdVirusAction.Action.QUARANTINE, 1, operatedBy);
            case "delete" -> doAction(findings, CmdVirusAction.Action.DELETE, 2, operatedBy);
            case "restore" -> doAction(findings, CmdVirusAction.Action.RESTORE, 3, operatedBy);
            case "whitelist" -> addWhitelist(findings, operatedBy);
            default -> throw new IllegalArgumentException("未知处置动作: " + action);
        }
        return Map.of("count", findings.size());
    }

    /** 下发本机文件处置指令 + 更新 finding 状态 */
    private void doAction(List<Map<String, Object>> findings, CmdVirusAction.Action act, int newStatus, Long operatedBy) {
        // 按 agent 分组下发（一次指令携带该主机全部目标）
        Map<String, List<VirusTarget>> byAgent = new java.util.LinkedHashMap<>();
        for (Map<String, Object> f : findings) {
            byAgent.computeIfAbsent((String) f.get("agent_id"), k -> new java.util.ArrayList<>())
                    .add(VirusTarget.newBuilder()
                            .setPath((String) f.get("path"))
                            .setSha256((String) f.get("sha256"))
                            .build());
        }
        String marks = findings.stream().map(f -> String.valueOf(f.get("id")))
                .reduce((a, b) -> a + "," + b).orElse("");
        for (var e : byAgent.entrySet()) {
            commandService.dispatch(e.getKey(), Command.newBuilder()
                    .setVirusAction(CmdVirusAction.newBuilder()
                            .setAction(act)
                            .addAllTargets(e.getValue())),
                    operatedBy);
        }
        jdbc.update("UPDATE t_virus_finding SET status = " + newStatus + " WHERE id IN (" + marks + ")");
        log.info("病毒处置指令已下发: action={} findings={} agents={}", act, findings.size(), byAgent.size());
    }

    /** 加白：写全局白名单、同步 Agent 策略，并将 finding 状态置 4。 */
    private void addWhitelist(List<Map<String, Object>> findings, Long operatedBy) {
        String marks = findings.stream().map(f -> String.valueOf(f.get("id")))
                .reduce((a, b) -> a + "," + b).orElse("");
        for (Map<String, Object> f : findings) {
            // hash 型白名单（跨路径全局生效）
            jdbc.update("""
                    INSERT INTO t_virus_whitelist (type, value, remark, created_by)
                    VALUES ('hash', ?, ?, ?)
                    """, f.get("sha256"), "检出记录加白: " + f.get("path"), operatedBy);
        }
        jdbc.update("UPDATE t_virus_finding SET status = 4 WHERE id IN (" + marks + ")");
        policyStore.rebuild();
        log.info("病毒检出已加白: findings={}", findings.size());
    }

    /** 新增白名单（管理入口：hash 或 path 型） */
    @Transactional
    public void addWhitelistEntry(String type, String value, String remark, Long operatedBy) {
        if (!"hash".equals(type) && !"path".equals(type)) {
            throw new IllegalArgumentException("白名单类型仅支持 hash / path");
        }
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("白名单值不能为空");
        }
        if ("hash".equals(type) && !value.matches("(?i)[0-9a-f]{64}")) {
            throw new IllegalArgumentException("hash 白名单需为 64 位十六进制 SHA256");
        }
        jdbc.update("INSERT INTO t_virus_whitelist (type, value, remark, created_by) VALUES (?, ?, ?, ?)",
                type, value, remark, operatedBy);
        policyStore.rebuild();
    }

    /** 删除白名单 */
    @Transactional
    public void removeWhitelist(long id) {
        int rows = jdbc.update("DELETE FROM t_virus_whitelist WHERE id = ?", id);
        if (rows == 0) {
            throw new IllegalArgumentException("白名单记录不存在");
        }
        policyStore.rebuild();
    }
}
