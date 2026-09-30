package com.alinksec.service.baseline;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.BaselineCheckSpec;
import com.alinksec.proto.CmdBaselineCheck;
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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 基线核查任务编排（docs/04 §4.3）：
 * 创建任务 → 按主机 OS 过滤适用检查项 → 逐台下发 baseline_check 指令。
 * 结构化检查项定义（check JSON）随指令下发即可热更新；命令型检查由 Agent
 * 内置白名单约束，未知命令不会被执行。
 */
@Service
public class BaselineTaskService {

    private static final Logger log = LoggerFactory.getLogger(BaselineTaskService.class);
    private static final DateTimeFormatter NO_FMT = DateTimeFormatter.ofPattern("yyyyMMddHHmmss");

    private final JdbcTemplate jdbc;
    private final CommandService commandService;
    private final DatabaseDialect database;

    public BaselineTaskService(JdbcTemplate jdbc, CommandService commandService, DatabaseDialect database) {
        this.jdbc = jdbc;
        this.commandService = commandService;
        this.database = database;
    }

    /**
     * 创建并下发核查任务。
     *
     * @param name        任务名（空则自动生成）
     * @param agentIds    目标主机（t_agent.agent_id）
     * @param templateIds 基线模板
     * @param createdBy   创建人（JWT uid）
     * @return 任务 id
     */
    @Transactional
    public long createTask(String name, List<String> agentIds, List<Long> templateIds, Long createdBy) {
        if (agentIds == null || agentIds.isEmpty()) {
            throw new IllegalArgumentException("请选择核查目标主机");
        }
        // 去重 + 去空（多选组件可能给出重复项）
        agentIds = agentIds.stream().filter(a -> a != null && !a.isBlank()).distinct().toList();
        if (agentIds.isEmpty()) {
            throw new IllegalArgumentException("请选择核查目标主机");
        }
        templateIds = templateIds == null ? List.of() : templateIds.stream().distinct().toList();
        if (templateIds.isEmpty()) {
            throw new IllegalArgumentException("请选择基线模板");
        }

        // 主机快照：agent_id + os_type（后续按 OS 过滤适用检查项）
        List<Map<String, Object>> agents = jdbc.queryForList("""
                SELECT agent_id, os_type FROM t_agent
                WHERE agent_id IN (%s)
                """.formatted(DatabaseDialect.placeholders(agentIds.size())), agentIds.toArray());
        if (agents.size() != agentIds.size()) {
            throw new IllegalArgumentException("部分主机不存在或已删除，请刷新后重选");
        }

        String taskNo = "BL" + LocalDateTime.now().format(NO_FMT)
                + ThreadLocalRandom.current().nextInt(100, 1000);
        long taskId = jdbc.queryForObject(
                "INSERT INTO t_baseline_task (task_no, name, scope, template_ids, status, created_by) "
                        + "VALUES (?, ?, ?, ?, 1, ?) RETURNING id",
                Long.class, taskNo,
                name == null || name.isBlank() ? taskNo + " 基线核查" : name,
                JsonUtils.write(Map.of("group_ids", List.of(), "agent_ids", agentIds)),
                database.encodeLongList(templateIds), createdBy);
        jdbc.update("UPDATE t_baseline_task SET started_at = CURRENT_TIMESTAMP WHERE id = ?", taskId);

        int dispatched = 0;
        for (Map<String, Object> agent : agents) {
            String agentId = (String) agent.get("agent_id");
            int osType = ((Number) agent.get("os_type")).intValue();
            CmdBaselineCheck.Builder check = buildCheckCommand(taskId, templateIds, osType);
            if (check.getItemsCount() == 0) {
                // 该 OS 无适用模板项：不入 scope 结果统计会卡进度，直接跳过下发
                log.info("主机无适用基线检查项，跳过下发: agent={} os_type={}", agentId, osType);
                continue;
            }
            commandService.dispatch(agentId, Command.newBuilder().setBaselineCheck(check), createdBy);
            dispatched++;
        }
        if (dispatched == 0) {
            throw new IllegalArgumentException("所选主机的操作系统无适用的基线模板（检查模板 os_type）");
        }
        log.info("基线核查任务已下发: task_id={} task_no={} agents={} templates={}",
                taskId, taskNo, dispatched, templateIds);
        return taskId;
    }

    /** 组装 CmdBaselineCheck：模板 × 启用项 × 主机 OS */
    private CmdBaselineCheck.Builder buildCheckCommand(long taskId, List<Long> templateIds, int osType) {
        List<Object> args = new ArrayList<>(templateIds);
        args.add(osType);
        List<Map<String, Object>> items = jdbc.queryForList("""
                SELECT i.id, CAST(i."check" AS TEXT) AS "check"
                FROM t_baseline_item i
                JOIN t_baseline_template t ON t.id = i.template_id
                WHERE t.id IN (%s) AND t.os_type = ? AND i.enabled
                ORDER BY i.id
                """.formatted(DatabaseDialect.placeholders(templateIds.size())), args.toArray());
        CmdBaselineCheck.Builder builder = CmdBaselineCheck.newBuilder()
                .setTaskId(String.valueOf(taskId))
                .addAllTemplateIds(templateIds.stream().map(String::valueOf)::iterator);
        for (Map<String, Object> item : items) {
            builder.addItems(BaselineCheckSpec.newBuilder()
                    .setItemId(String.valueOf(item.get("id")))
                    .setCheck(String.valueOf(item.get("check"))));
        }
        return builder;
    }

    /**
     * 任务超时兜底：执行中超 30 分钟仍未收齐结果 → 部分失败（已收结果保留，
     * Agent 后续补传仍会更新汇总与进度）。
     */
    @Scheduled(fixedDelay = 60_000, initialDelay = 90_000)
    public void sweepTimeout() {
        int rows = jdbc.update("""
                UPDATE t_baseline_task SET status = 3, finished_at = CURRENT_TIMESTAMP
                WHERE status = 1 AND created_at < ?
                """, database.timestampBefore(Duration.ofMinutes(30)));
        if (rows > 0) {
            log.warn("基线任务超时置部分失败: count={}", rows);
        }
    }

}
