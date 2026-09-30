package com.alinksec.service.virus;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.CmdVirusScan;
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
 * 病毒扫描任务编排（docs/05 §1.3）：
 * mode：1快速（关键路径）2全盘（限速 10MB/s）3自定义（指定路径）。
 * 检出由 Agent 默认隔离，结果经 RptVirusResult 回传。
 */
@Service
public class VirusTaskService {

    private static final Logger log = LoggerFactory.getLogger(VirusTaskService.class);
    private static final DateTimeFormatter NO_FMT = DateTimeFormatter.ofPattern("yyyyMMddHHmmss");

    public static final int MODE_QUICK = 1;
    public static final int MODE_FULL = 2;
    public static final int MODE_CUSTOM = 3;

    private final JdbcTemplate jdbc;
    private final CommandService commandService;
    private final DatabaseDialect database;

    public VirusTaskService(JdbcTemplate jdbc, CommandService commandService, DatabaseDialect database) {
        this.jdbc = jdbc;
        this.commandService = commandService;
        this.database = database;
    }

    /** 创建并下发病毒扫描任务。paths 仅 CUSTOM 模式使用。 */
    @Transactional
    public long createTask(String name, List<String> agentIds, int mode, List<String> paths, Long createdBy) {
        agentIds = agentIds == null ? List.of()
                : agentIds.stream().filter(a -> a != null && !a.isBlank()).distinct().toList();
        if (agentIds.isEmpty()) {
            throw new IllegalArgumentException("请选择扫描目标主机");
        }
        if (mode != MODE_QUICK && mode != MODE_FULL && mode != MODE_CUSTOM) {
            throw new IllegalArgumentException("扫描模式非法");
        }
        if (mode == MODE_CUSTOM && (paths == null || paths.isEmpty())) {
            throw new IllegalArgumentException("自定义扫描需指定路径");
        }
        Integer exists = jdbc.queryForObject(
                "SELECT count(*) FROM t_agent WHERE agent_id IN ("
                        + DatabaseDialect.placeholders(agentIds.size()) + ") AND deleted = false",
                Integer.class, agentIds.toArray());
        if (exists == null || exists != agentIds.size()) {
            throw new IllegalArgumentException("部分主机不存在或已删除，请刷新后重选");
        }
        // 特征库未导入直接拒绝（Agent 空跑无意义）
        Integer dbCount = jdbc.queryForObject("SELECT count(*) FROM t_virus_db", Integer.class);
        if (dbCount == null || dbCount == 0) {
            throw new IllegalArgumentException("特征库尚未导入，请先在特征库管理上传");
        }

        String taskNo = "VS" + LocalDateTime.now().format(NO_FMT)
                + ThreadLocalRandom.current().nextInt(100, 1000);
        List<String> cleanPaths = mode == MODE_CUSTOM
                ? paths.stream().filter(p -> p != null && !p.isBlank()).toList() : List.of();
        long taskId = jdbc.queryForObject(
                "INSERT INTO t_virus_scan_task (task_no, name, mode, scope, status, created_by) "
                        + "VALUES (?, ?, ?, ?, 1, ?) RETURNING id",
                Long.class, taskNo,
                name == null || name.isBlank() ? taskNo + " 病毒扫描" : name,
                mode, JsonUtils.write(Map.of("agent_ids", agentIds, "paths", cleanPaths)),
                createdBy);
        jdbc.update("UPDATE t_virus_scan_task SET started_at = CURRENT_TIMESTAMP WHERE id = ?", taskId);

        CmdVirusScan.Builder cmd = CmdVirusScan.newBuilder()
                .setTaskId(String.valueOf(taskId))
                .setMode(mode == MODE_FULL ? CmdVirusScan.Mode.FULL
                        : mode == MODE_CUSTOM ? CmdVirusScan.Mode.CUSTOM : CmdVirusScan.Mode.QUICK);
        cmd.addAllPaths(cleanPaths);
        for (String agentId : agentIds) {
            commandService.dispatch(agentId, Command.newBuilder().setVirusScan(cmd), createdBy);
        }
        log.info("病毒扫描任务已下发: task_id={} task_no={} agents={} mode={}",
                taskId, taskNo, agentIds.size(), mode);
        return taskId;
    }

    /** 任务超时兜底：执行中超 2 小时（全盘扫描大主机）→ 部分失败（已收结果保留） */
    @Scheduled(fixedDelay = 120_000, initialDelay = 180_000)
    public void sweepTimeout() {
        int rows = jdbc.update("""
                UPDATE t_virus_scan_task SET status = 3, finished_at = CURRENT_TIMESTAMP
                WHERE status = 1 AND created_at < ?
                """, database.timestampBefore(Duration.ofHours(2)));
        if (rows > 0) {
            log.warn("病毒扫描任务超时置部分失败: count={}", rows);
        }
    }

    /**
     * 定时快扫策略（docs/05 §1.3：定时策略默认每周一次）：
     * 每周一 02:30 对全部在线主机下发快速扫描；特征库未导入时跳过。
     * cron 可配（alinksec.virus.weekly-scan-cron），设为 "-" 可关闭。
     */
    @Scheduled(cron = "${alinksec.virus.weekly-scan-cron:0 30 2 * * MON}")
    public void weeklyQuickScan() {
        Integer dbCount = jdbc.queryForObject("SELECT count(*) FROM t_virus_db", Integer.class);
        if (dbCount == null || dbCount == 0) {
            return; // 特征库未导入：快扫无意义，跳过（不刷日志噪音）
        }
        List<String> agents = jdbc.queryForList(
                "SELECT agent_id FROM t_agent WHERE deleted = false AND status = 1", String.class);
        if (agents.isEmpty()) {
            return;
        }
        try {
            createTask("定时快扫（每周策略）", agents, MODE_QUICK, List.of(), null);
        } catch (Exception e) {
            log.warn("定时快扫下发失败: {}", e.getMessage());
        }
    }

}
