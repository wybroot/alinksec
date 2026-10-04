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

    /** Empty templateIds selects all published templates applicable to each Agent. */
    @Transactional
    public long createTask(String name, List<String> agentIds, List<Long> templateIds, Long createdBy) {
        return create(name, agentIds, templateIds, createdBy, false);
    }

    @Transactional
    public long createReviewTask(String name, List<String> agentIds, long templateId, Long createdBy) {
        return create(name, agentIds, List.of(templateId), createdBy, true);
    }

    public List<Map<String, Object>> coverage(List<String> agentIds, List<Long> templateIds) {
        return coverage(plan(agentIds, templateIds, false));
    }

    private record Plan(List<Map<String, Object>> agents, List<Map<String, Object>> templates,
                        List<Map<String, Object>> items) {}

    private Plan plan(List<String> agentIds, List<Long> templateIds, boolean review) {
        if (agentIds == null || agentIds.isEmpty() || agentIds.size() > 500 || agentIds.stream().anyMatch(a -> a == null || a.isBlank())) {
            throw new IllegalArgumentException("请选择 1 至 500 台核查主机");
        }
        agentIds = agentIds.stream().distinct().toList();
        templateIds = templateIds == null ? List.of() : templateIds.stream().distinct().toList();
        if (templateIds.size() > 50 || templateIds.stream().anyMatch(id -> id == null || id <= 0)) {
            throw new IllegalArgumentException("模板选择无效或超过 50 项");
        }
        List<Map<String, Object>> agents = jdbc.queryForList("SELECT agent_id,os_type,os_version FROM t_agent WHERE deleted=false AND agent_id IN ("
                + DatabaseDialect.placeholders(agentIds.size()) + ")", agentIds.toArray());
        if (agents.size() != agentIds.size()) throw new IllegalArgumentException("部分主机不存在或已删除，请刷新后重选");
        List<Map<String, Object>> templates = jdbc.queryForList("SELECT * FROM t_baseline_template"
                + (templateIds.isEmpty() ? " WHERE enabled" : " WHERE id IN (" + DatabaseDialect.placeholders(templateIds.size()) + ")")
                + " ORDER BY id", templateIds.toArray());
        if (!templateIds.isEmpty() && (templates.size() != templateIds.size()
                || !review && templates.stream().anyMatch(t -> !DatabaseDialect.readBoolean(t.get("enabled"))))) {
            throw new IllegalArgumentException("部分模板不存在、未发布或已撤回，请刷新后重选");
        }
        List<Long> applicable = templates.stream().filter(t -> agents.stream().anyMatch(a -> applies(t, a)))
                .map(t -> ((Number) t.get("id")).longValue()).toList();
        List<Map<String, Object>> items = applicable.isEmpty() ? List.of() : jdbc.queryForList("""
                SELECT id,template_id,code,name,category,severity,CAST("check" AS TEXT) AS "check",
                       remediation,CAST(fix_spec AS TEXT) AS fix_spec,rule_id
                FROM t_baseline_item WHERE enabled AND template_id IN (%s) ORDER BY id
                """.formatted(DatabaseDialect.placeholders(applicable.size())), applicable.toArray());
        return new Plan(agents, templates, items);
    }

    private static boolean applies(Map<String, Object> template, Map<String, Object> agent) {
        return BaselinePackageFormat.applies(((Number) template.get("os_type")).intValue(),
                (String) template.get("os_version_pattern"), agent);
    }
    private static List<Map<String, Object>> agentItems(Plan plan, Map<String, Object> agent) {
        var ids = plan.templates.stream().filter(t -> applies(t, agent)).map(t -> ((Number) t.get("id")).longValue()).toList();
        return plan.items.stream().filter(i -> ids.contains(((Number) i.get("template_id")).longValue())).toList();
    }
    private static List<Map<String, Object>> coverage(Plan plan) {
        List<Map<String, Object>> result = new ArrayList<>();
        for (var agent : plan.agents) {
            var items = agentItems(plan, agent);
            var templates = plan.templates.stream().filter(t -> applies(t, agent)
                    && items.stream().anyMatch(i -> ((Number) i.get("template_id")).longValue() == ((Number) t.get("id")).longValue()))
                    .map(t -> Map.of("id", t.get("id"), "name", t.get("name"), "version", t.get("version"))).toList();
            Map<String, Object> row = new java.util.LinkedHashMap<>(agent);
            row.put("templates", templates); row.put("itemCount", items.size()); row.put("covered", !items.isEmpty());
            result.add(row);
        }
        return result;
    }

    private long create(String name, List<String> agentIds, List<Long> templateIds, Long createdBy, boolean review) {
        if (name != null && name.length() > 128) throw new IllegalArgumentException("任务名称不能超过 128 字");
        Plan plan = plan(agentIds, templateIds, review);
        var uncovered = coverage(plan).stream().filter(row -> !Boolean.TRUE.equals(row.get("covered"))).map(row -> row.get("agent_id")).toList();
        if (!uncovered.isEmpty()) throw new IllegalArgumentException("以下主机没有已发布且适用的检查项: " + uncovered);
        // Freeze this selection before locking. A newly published series may be
        // selected by the next task, but cannot enter this one without its lock.
        var selectedIds = plan.items.stream().map(item -> ((Number) item.get("template_id")).longValue()).distinct().toList();
        var packageIds = plan.templates.stream().filter(t -> selectedIds.contains(((Number) t.get("id")).longValue()) && t.get("package_id") != null)
                .map(t -> String.valueOf(t.get("package_id"))).distinct().toList();
        // All baseline task/repair operations use the same code ordering.
        if (!packageIds.isEmpty()) jdbc.queryForList("SELECT DISTINCT code FROM t_baseline_package WHERE id IN ("
                + DatabaseDialect.placeholders(packageIds.size()) + ") ORDER BY code", String.class, packageIds.toArray())
                .forEach(code -> jdbc.update("UPDATE t_baseline_package_gate SET revision=revision+1 WHERE code=?", code));
        plan = plan(agentIds, selectedIds, review);
        uncovered = coverage(plan).stream().filter(row -> !Boolean.TRUE.equals(row.get("covered"))).map(row -> row.get("agent_id")).toList();
        if (!uncovered.isEmpty()) throw new IllegalArgumentException("以下主机没有已发布且适用的检查项: " + uncovered);
        if (coverage(plan).stream().anyMatch(row -> ((Number) row.get("itemCount")).intValue() > 500)) {
            throw new IllegalArgumentException("每台主机单次最多下发 500 项检查，请缩小模板集合");
        }
        List<Long> selected = plan.items.stream().map(i -> ((Number) i.get("template_id")).longValue()).distinct().toList();
        String taskNo = "BL" + LocalDateTime.now().format(NO_FMT) + java.util.UUID.randomUUID().toString().substring(0, 8);
        long taskId = jdbc.queryForObject("INSERT INTO t_baseline_task(task_no,name,scope,template_ids,status,created_by,started_at) "
                + "VALUES (?,?,?,?,1,?,CURRENT_TIMESTAMP) RETURNING id", Long.class, taskNo,
                name == null || name.isBlank() ? taskNo + " 基线核查" : name,
                JsonUtils.write(Map.of("group_ids", List.of(), "agent_ids", plan.agents.stream().map(a -> a.get("agent_id")).toList())),
                database.encodeLongList(selected), createdBy);
        for (var template : plan.templates) if (selected.contains(((Number) template.get("id")).longValue())) {
            String digest = template.get("package_id") == null ? null : jdbc.queryForObject("SELECT content_sha256 FROM t_baseline_package WHERE id=?", String.class, template.get("package_id"));
            jdbc.update("INSERT INTO t_baseline_task_template(task_id,template_id,code,name,version,package_id,content_sha256) VALUES (?,?,?,?,?,?,?)",
                    taskId, template.get("id"), template.get("code"), template.get("name"), template.get("version"), template.get("package_id"), digest);
        }
        for (var item : plan.items) jdbc.update("""
                INSERT INTO t_baseline_task_item(task_id,item_id,template_id,code,name,category,severity,"check",remediation,fix_spec,rule_id)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """, taskId, item.get("id"), item.get("template_id"), item.get("code"), item.get("name"), item.get("category"),
                item.get("severity"), item.get("check"), item.get("remediation"), item.get("fix_spec"), item.get("rule_id"));
        for (var agent : plan.agents) {
            String agentId = (String) agent.get("agent_id");
            var items = agentItems(plan, agent);
            var check = CmdBaselineCheck.newBuilder().setTaskId(String.valueOf(taskId))
                    .addAllTemplateIds(items.stream().map(i -> String.valueOf(i.get("template_id"))).distinct().toList());
            for (var item : items) {
                jdbc.update("INSERT INTO t_baseline_task_expected(task_id,agent_id,item_id) VALUES (?,?,?)", taskId, agentId, item.get("id"));
                check.addItems(BaselineCheckSpec.newBuilder().setItemId(String.valueOf(item.get("id"))).setCheck(String.valueOf(item.get("check"))));
            }
            commandService.dispatchAfterCommit(agentId, Command.newBuilder().setBaselineCheck(check), createdBy);
        }
        log.info("基线核查任务已下发: task_id={} agents={} templates={}", taskId, plan.agents.size(), selected);
        return taskId;
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
