package com.alinksec.service.scan;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.CmdVulnScan;
import com.alinksec.proto.Command;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.config.DatabaseDialect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.Duration;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 安全扫描任务编排（docs/04 §4）：弱口令 + 端口服务（Agent 执行）+ 漏洞比对（服务端执行）。
 * type 位组合：1漏洞 2弱口令 4端口服务。
 */
@Service
public class ScanTaskService {

    private static final Logger log = LoggerFactory.getLogger(ScanTaskService.class);
    private static final DateTimeFormatter NO_FMT = DateTimeFormatter.ofPattern("yyyyMMddHHmmss");

    /** t_scan_task.type 位定义 */
    public static final int TYPE_VULN = 1;
    public static final int TYPE_WEAK_PWD = 2;
    public static final int TYPE_PORT = 4;

    private final JdbcTemplate jdbc;
    private final CommandService commandService;
    private final VulnMatchService vulnMatchService;
    private final DatabaseDialect database;

    public ScanTaskService(JdbcTemplate jdbc, CommandService commandService,
                           VulnMatchService vulnMatchService, DatabaseDialect database) {
        this.jdbc = jdbc;
        this.commandService = commandService;
        this.vulnMatchService = vulnMatchService;
        this.database = database;
    }

    /**
     * 创建并下发扫描任务。
     *
     * @param includeWeakPassword 弱口令策略检测（Agent 本机 shadow 分析）
     * @param includePortService  端口服务识别（Agent 本地监听表 + 指纹）
     * @param includeVuln         漏洞比对（服务端 t_cve_db × 软件快照，即时完成）
     */
    @Transactional
    public long createTask(String name, List<String> agentIds,
                           boolean includeWeakPassword, boolean includePortService,
                           boolean includeVuln, Long createdBy) {
        agentIds = agentIds == null ? List.of()
                : agentIds.stream().filter(a -> a != null && !a.isBlank()).distinct().toList();
        if (agentIds.isEmpty()) {
            throw new IllegalArgumentException("请选择扫描目标主机");
        }
        if (!includeWeakPassword && !includePortService && !includeVuln) {
            throw new IllegalArgumentException("请至少选择一项扫描内容");
        }
        int exists = jdbc.queryForObject(
                "SELECT count(*) FROM t_agent WHERE agent_id IN ("
                        + DatabaseDialect.placeholders(agentIds.size()) + ")",
                Integer.class, agentIds.toArray());
        if (exists != agentIds.size()) {
            throw new IllegalArgumentException("部分主机不存在或已删除，请刷新后重选");
        }

        int type = (includeVuln ? TYPE_VULN : 0) | (includeWeakPassword ? TYPE_WEAK_PWD : 0)
                | (includePortService ? TYPE_PORT : 0);
        String taskNo = "SC" + LocalDateTime.now().format(NO_FMT)
                + ThreadLocalRandom.current().nextInt(100, 1000);
        long taskId = jdbc.queryForObject(
                "INSERT INTO t_scan_task (task_no, name, type, scope, status, created_by) "
                        + "VALUES (?, ?, ?, ?, 1, ?) RETURNING id",
                Long.class, taskNo,
                name == null || name.isBlank() ? taskNo + " 安全扫描" : name,
                type, JsonUtils.write(Map.of(
                        "agent_ids", agentIds,
                        "include_weak_password", includeWeakPassword,
                        "include_port_service", includePortService)),
                createdBy);
        jdbc.update("UPDATE t_scan_task SET started_at = CURRENT_TIMESTAMP WHERE id = ?", taskId);

        // 漏洞比对：服务端即时完成（用最新软件快照）
        if (includeVuln) {
            for (String agentId : agentIds) {
                try {
                    vulnMatchService.matchAgent(agentId, taskId);
                } catch (Exception e) {
                    log.warn("漏洞比对失败: agent={} err={}", agentId, e.getMessage());
                }
            }
        }
        // 弱口令 / 端口服务：下发指令由 Agent 执行（无 agent 侧内容时直接完成）
        if (includeWeakPassword || includePortService) {
            for (String agentId : agentIds) {
                commandService.dispatch(agentId, Command.newBuilder()
                        .setVulnScan(CmdVulnScan.newBuilder()
                                .setTaskId(String.valueOf(taskId))
                                .setIncludeWeakPassword(includeWeakPassword)
                                .setIncludePortService(includePortService)),
                        createdBy);
            }
        } else {
            jdbc.update("UPDATE t_scan_task SET status = 2, progress = 100, finished_at = CURRENT_TIMESTAMP "
                    + "WHERE id = ?", taskId);
        }
        log.info("安全扫描任务已下发: task_id={} task_no={} agents={} type={}",
                taskId, taskNo, agentIds.size(), type);
        return taskId;
    }

    /** 任务超时兜底：执行中超 30 分钟 → 部分失败（已收结果保留） */
    @Scheduled(fixedDelay = 60_000, initialDelay = 120_000)
    public void sweepTimeout() {
        int rows = jdbc.update("""
                UPDATE t_scan_task SET status = 3, finished_at = CURRENT_TIMESTAMP
                WHERE status = 1 AND created_at < ?
                """, database.timestampBefore(Duration.ofMinutes(30)));
        if (rows > 0) {
            log.warn("扫描任务超时置部分失败: count={}", rows);
        }
    }

}
