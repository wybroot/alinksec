package com.alinksec.service.fix;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.CmdVulnFix;
import com.alinksec.proto.Command;
import com.alinksec.proto.FixItem;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.config.DatabaseDialect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.Duration;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 配置类一键修复任务编排（docs/05 §3）：
 * 目标来自基线核查失败项（t_baseline_item.fix_spec）。
 * risk=manual 的项不支持自动修复（需人工）；payload = fix_spec + check 合并（Agent 复核用）。
 */
@Service
public class FixTaskService {

    private static final Logger log = LoggerFactory.getLogger(FixTaskService.class);
    private static final DateTimeFormatter NO_FMT = DateTimeFormatter.ofPattern("yyyyMMddHHmmss");

    private final JdbcTemplate jdbc;
    private final CommandService commandService;
    private final PatchRepoService patchRepo;
    private final DatabaseDialect database;

    public FixTaskService(JdbcTemplate jdbc, CommandService commandService, PatchRepoService patchRepo,
                          DatabaseDialect database) {
        this.jdbc = jdbc;
        this.commandService = commandService;
        this.patchRepo = patchRepo;
        this.database = database;
    }

    /**
     * 创建并下发修复任务。
     *
     * @param name     任务名
     * @param items    修复目标：agentId + itemId（t_baseline_item.id，须有 fix_spec）
     * @param createdBy 创建人
     * @return 任务 id
     */
    @Transactional
    public long createTask(String name, List<Map<String, Object>> items, Long createdBy) {
        if (items == null || items.isEmpty() || items.size() > 500) {
            throw new IllegalArgumentException("请选择 1 至 500 项修复目标");
        }
        // 归一化输入：agentId + itemId
        record Target(String agentId, long itemId) {}
        List<Target> targets = new ArrayList<>();
        for (Map<String, Object> it : items) {
            String agentId = it.get("agentId") instanceof String value ? value : "";
            long itemId = it.get("itemId") instanceof Number n ? n.longValue() : -1;
            if (agentId.isBlank() || itemId <= 0) {
                throw new IllegalArgumentException("修复项格式非法（需 agentId + itemId）");
            }
            targets.add(new Target(agentId, itemId));
        }

        // 基线项快照：fix_spec + check（一次查全，去重 itemId）
        List<Long> itemIds = targets.stream().map(Target::itemId).distinct().toList();
        jdbc.queryForList("""
                SELECT DISTINCT p.code FROM t_baseline_item i JOIN t_baseline_template t ON t.id=i.template_id
                JOIN t_baseline_package p ON p.id=t.package_id WHERE i.id IN (%s) ORDER BY p.code
                """.formatted(DatabaseDialect.placeholders(itemIds.size())), String.class, itemIds.toArray())
                .forEach(code -> jdbc.update("UPDATE t_baseline_package_gate SET revision=revision+1 WHERE code=?", code));
        Map<Long, Map<String, Object>> specs = new LinkedHashMap<>();
        for (Map<String, Object> row : jdbc.queryForList("""
                SELECT i.id, i.code, i.name, CAST(i.fix_spec AS TEXT) AS fix_spec,
                       CAST(i."check" AS TEXT) AS "check",t.os_type,t.os_version_pattern
                FROM t_baseline_item i JOIN t_baseline_template t ON t.id=i.template_id
                WHERE i.enabled AND t.enabled AND i.id IN (%s)
                """.formatted(DatabaseDialect.placeholders(itemIds.size())), itemIds.toArray())) {
            specs.put(((Number) row.get("id")).longValue(), row);
        }

        // 校验 + 构造下发内容
        Map<String, List<FixItem>> byAgent = new LinkedHashMap<>();
        List<Map<String, Object>> targetRows = new ArrayList<>();
        for (Target t : targets) {
            Map<String, Object> spec = specs.get(t.itemId());
            if (spec == null) {
                throw new IllegalArgumentException("基线项不存在、未启用或模板已撤回: " + t.itemId());
            }
            var host = jdbc.queryForList("SELECT os_type,os_version FROM t_agent WHERE agent_id=? AND deleted=false", t.agentId());
            if (host.size() != 1 || !com.alinksec.service.baseline.BaselinePackageFormat.applies(
                    ((Number) spec.get("os_type")).intValue(), (String) spec.get("os_version_pattern"), host.get(0))) {
                throw new IllegalArgumentException("基线修复不适用于当前主机系统: " + t.agentId());
            }
            var evidence = jdbc.queryForList("""
                    SELECT r.passed,i.fix_current FROM t_baseline_result r
                    JOIN v_baseline_result_definition i ON i.result_id=r.id
                    WHERE r.agent_id=? AND r.item_id=? ORDER BY r.task_id DESC,r.id DESC LIMIT 1
                    """, t.agentId(), t.itemId());
            if (evidence.isEmpty() || DatabaseDialect.readBoolean(evidence.get(0).get("passed"))
                    || !DatabaseDialect.readBoolean(evidence.get(0).get("fix_current"))) {
                throw new IllegalArgumentException("缺少适用的未通过核查结果，或结果定义已过期，请重新核查: " + t.itemId());
            }
            String fixSpec = (String) spec.get("fix_spec");
            if (fixSpec == null || fixSpec.isBlank() || "null".equals(fixSpec)) {
                throw new IllegalArgumentException("基线项 " + spec.get("code") + " 不支持自动修复（无 fix_spec）");
            }
            String risk = JsonUtils.read(fixSpec).path("risk").asText("auto");
            if ("manual".equals(risk)) {
                throw new IllegalArgumentException("基线项 " + spec.get("code") + " 风险等级为 manual，需人工修复");
            }
            // payload：fix_spec 与 check 合并（Agent 修复后重跑 check 复核）
            Map<String, Object> payload = JsonUtils.read(fixSpec, Map.class);
            payload.put("check", spec.get("check"));
            byAgent.computeIfAbsent(t.agentId(), k -> new ArrayList<>())
                    .add(FixItem.newBuilder()
                            .setRefId(String.valueOf(t.itemId()))
                            .setType(FixItem.FixType.CONFIG)
                            .setPayload(JsonUtils.write(payload))
                            .build());
            targetRows.add(Map.of("ref_type", "baseline_item",
                    "ref_id", String.valueOf(t.itemId()),
                    "agent_id", t.agentId(),
                    "fix_payload", JsonUtils.write(payload)));
        }

        // 主机存在性校验
        List<String> agentIds = List.copyOf(byAgent.keySet());
        Integer exists = jdbc.queryForObject(
                "SELECT count(*) FROM t_agent WHERE agent_id IN ("
                        + DatabaseDialect.placeholders(agentIds.size()) + ") AND deleted = false",
                Integer.class, agentIds.toArray());
        if (exists == null || exists != agentIds.size()) {
            throw new IllegalArgumentException("部分主机不存在或已删除，请刷新后重选");
        }

        String taskNo = "FX" + LocalDateTime.now().format(NO_FMT)
                + ThreadLocalRandom.current().nextInt(100, 1000);
        long taskId = jdbc.queryForObject(
                "INSERT INTO t_fix_task (task_no, name, type, scope, targets, status, created_by) "
                        + "VALUES (?, ?, 1, ?, ?, 1, ?) RETURNING id",
                Long.class, taskNo,
                name == null || name.isBlank() ? taskNo + " 配置修复" : name,
                JsonUtils.write(Map.of("agent_ids", agentIds)),
                JsonUtils.write(targetRows), createdBy);
        jdbc.update("UPDATE t_fix_task SET started_at = CURRENT_TIMESTAMP WHERE id = ?", taskId);

        // 预写 t_fix_record（待执行），结果上报按 task+agent+ref 更新
        for (Map<String, Object> row : targetRows) {
            jdbc.update("""
                    INSERT INTO t_fix_record (task_id, agent_id, ref_id, ref_type)
                    VALUES (?, ?, ?, 'baseline_item')
                    """, taskId, row.get("agent_id"), row.get("ref_id"));
        }

        for (var e : byAgent.entrySet()) {
            commandService.dispatchAfterCommit(e.getKey(), Command.newBuilder()
                    .setVulnFix(CmdVulnFix.newBuilder()
                            .setTaskId(String.valueOf(taskId))
                            .addAllFixes(e.getValue())),
                    createdBy);
        }
        log.info("配置修复任务已下发: task_id={} task_no={} agents={} items={}",
                taskId, taskNo, agentIds.size(), targets.size());
        return taskId;
    }

    /** 任务超时兜底：执行中超 30 分钟 → 部分失败（已收结果保留） */
    @Scheduled(fixedDelay = 120_000, initialDelay = 150_000)
    public void sweepTimeout() {
        int rows = jdbc.update("""
                UPDATE t_fix_task SET status = 3, finished_at = CURRENT_TIMESTAMP
                WHERE status = 1 AND created_at < ?
                """, database.timestampBefore(Duration.ofMinutes(30)));
        if (rows > 0) {
            log.warn("修复任务超时置部分失败: count={}", rows);
        }
    }

    /* ================================================================
     * 软件包类修复（docs/05 §3.3）：审批 + 维护窗口 + 补丁覆盖率校验
     * ================================================================ */

    /**
     * 创建软件包类修复任务（不立即下发；审批通过且进入维护窗口后由 dispatchApproved 派发）。
     *
     * @param items       [{agentId, findingId}]（t_vuln_finding，须有 fixed_version）
     * @param approver    审批人（必填）
     * @param windowStart 维护窗口起（ISO 本地时间，空 = 审批后立即执行）
     * @param windowEnd   维护窗口止（可选，仅展示约束）
     */
    @Transactional
    public Map<String, Object> createPackageTask(String name, List<Map<String, Object>> items,
                                                 String approver, String windowStart, String windowEnd,
                                                 Long createdBy) {
        if (items == null || items.isEmpty()) {
            throw new IllegalArgumentException("请选择修复项");
        }
        if (approver == null || approver.isBlank()) {
            throw new IllegalArgumentException("软件包类修复必须指定审批人");
        }
        // 漏洞快照：finding + 主机 OS + 目标版本
        List<Long> findingIds = items.stream()
                .map(it -> it.get("findingId") instanceof Number n ? n.longValue() : -1L)
                .filter(id -> id > 0).distinct().toList();
        if (findingIds.size() != items.size() || findingIds.isEmpty()) {
            throw new IllegalArgumentException("修复项格式非法（需 agentId + findingId）");
        }
        Map<Long, Map<String, Object>> findings = new LinkedHashMap<>();
        for (Map<String, Object> row : jdbc.queryForList("""
                SELECT f.id, f.agent_id, f.cve_id, f.software, f.installed_version, f.fixed_version, f.status,
                       a.os_type, a.os_version
                FROM t_vuln_finding f JOIN t_agent a ON a.agent_id = f.agent_id AND a.deleted = false
                WHERE f.id IN (%s)
                """.formatted(DatabaseDialect.placeholders(findingIds.size())), findingIds.toArray())) {
            findings.put(((Number) row.get("id")).longValue(), row);
        }

        // 覆盖率校验 + payload 构造
        List<Map<String, Object>> resolveTargets = new ArrayList<>();
        for (Map<String, Object> it : items) {
            String agentId = String.valueOf(it.get("agentId"));
            long fid = it.get("findingId") instanceof Number n ? n.longValue() : -1;
            Map<String, Object> f = findings.get(fid);
            if (f == null || !agentId.equals(String.valueOf(f.get("agent_id")))) {
                throw new IllegalArgumentException("漏洞项不存在或与主机不匹配: finding=" + fid);
            }
            if (((Number) f.get("status")).intValue() > 1) {
                throw new IllegalArgumentException("漏洞项已处置，请刷新后重选: finding=" + fid);
            }
            if (f.get("fixed_version") == null || String.valueOf(f.get("fixed_version")).isBlank()) {
                throw new IllegalArgumentException("漏洞 " + f.get("cve_id") + " 无修复版本信息，需人工处理");
            }
            resolveTargets.add(Map.of(
                    "agent_id", agentId,
                    "os_type", f.get("os_type"),
                    "os_version", f.get("os_version") == null ? "" : f.get("os_version"),
                    "pkg_name", f.get("software"),
                    "target_version", f.get("fixed_version"),
                    "cve_id", f.get("cve_id"),
                    "finding_id", fid));
        }
        PatchRepoService.Resolved resolved = patchRepo.resolveForAgents(resolveTargets);
        if (!resolved.missing().isEmpty()) {
            // 补丁仓库未覆盖 → 阻断创建，返回缺失清单（docs/05：禁止执行未覆盖安装）
            throw new IllegalArgumentException("以下补丁未导入仓库，已阻断创建：\n" + String.join("\n", resolved.missing()));
        }

        // 构造下发内容（refId = finding id，结果上报据此回写漏洞状态）
        Map<String, List<FixItem>> byAgent = new LinkedHashMap<>();
        List<Map<String, Object>> targetRows = new ArrayList<>();
        for (Map<String, Object> t : resolveTargets) {
            Map<String, Object> patch = resolved.hits().get(t.get("agent_id") + ":" + t.get("finding_id"));
            Map<String, Object> payload = Map.of(
                    "repo_type", patch.get("repo_type"),
                    "pkg_name", t.get("pkg_name"),
                    "target_version", t.get("target_version"),
                    "download_url", patchRepo.downloadUrl(String.valueOf(t.get("agent_id")), patch),
                    "sha256", patch.get("sha256"),
                    "cve_id", t.get("cve_id"),
                    "finding_id", String.valueOf(t.get("finding_id")));
            byAgent.computeIfAbsent(String.valueOf(t.get("agent_id")), k -> new ArrayList<>())
                    .add(FixItem.newBuilder()
                            .setRefId(String.valueOf(t.get("finding_id")))
                            .setType(FixItem.FixType.PACKAGE)
                            .setPayload(JsonUtils.write(payload))
                            .build());
            targetRows.add(Map.of("ref_type", "vuln_finding",
                    "ref_id", String.valueOf(t.get("finding_id")),
                    "agent_id", t.get("agent_id"),
                    "fix_payload", JsonUtils.write(payload)));
        }

        String taskNo = "FP" + LocalDateTime.now().format(NO_FMT)
                + ThreadLocalRandom.current().nextInt(100, 1000);
        OffsetDateTime ws = parseTime(windowStart), we = parseTime(windowEnd);
        long taskId = jdbc.queryForObject(
                "INSERT INTO t_fix_task (task_no, name, type, scope, targets, status, created_by, approver, "
                        + "approved, window_start, window_end) "
                        + "VALUES (?, ?, 2, ?, ?, 0, ?, ?, false, ?, ?) RETURNING id",
                Long.class, taskNo,
                name == null || name.isBlank() ? taskNo + " 软件包修复" : name,
                JsonUtils.write(Map.of("agent_ids", List.copyOf(byAgent.keySet()))),
                JsonUtils.write(targetRows), createdBy, approver, database.timestamp(ws), database.timestamp(we));

        // 预写 t_fix_record（待执行/待审批派发）
        for (Map<String, Object> row : targetRows) {
            jdbc.update("""
                    INSERT INTO t_fix_record (task_id, agent_id, ref_id, ref_type)
                    VALUES (?, ?, ?, 'vuln_finding')
                    """, taskId, row.get("agent_id"), row.get("ref_id"));
        }
        log.info("软件包修复任务已创建（待审批）: task_id={} task_no={} approver={} items={}",
                taskId, taskNo, approver, targetRows.size());
        return Map.of("taskId", taskId, "taskNo", taskNo, "pendingApprove", true);
    }

    /** 审批通过：置 approved；窗口为空或已到 → 立即派发，否则等调度器 */
    @Transactional
    public Map<String, Object> approve(long taskId, String operator) {
        Map<String, Object> task = jdbc.queryForMap(
                "SELECT id, type, status, approved, approver, window_start FROM t_fix_task WHERE id = ?", taskId);
        if (((Number) task.get("type")).intValue() != 2) {
            throw new IllegalArgumentException("仅软件包类任务需审批");
        }
        if (isTrue(task.get("approved"))) {
            return Map.of("taskId", taskId, "state", "already");
        }
        jdbc.update("UPDATE t_fix_task SET approved = true, approved_at = CURRENT_TIMESTAMP, approver = COALESCE(?, approver) "
                + "WHERE id = ?", operator, taskId);
        boolean inWindow = task.get("window_start") == null
                || !OffsetDateTime.now().isBefore(database.readOffsetDateTime(task.get("window_start")));
        if (inWindow) {
            dispatchApproved(taskId);
            return Map.of("taskId", taskId, "state", "dispatched");
        }
        return Map.of("taskId", taskId, "state", "waiting_window");
    }

    /** 维护窗口调度：已审批未派发且窗口已到 → 派发（每分钟） */
    @Scheduled(fixedDelay = 60_000, initialDelay = 60_000)
    public void dispatchWindowReached() {
        List<Long> ids = jdbc.queryForList("""
                SELECT id FROM t_fix_task
                WHERE type = 2 AND approved = true AND dispatched_at IS NULL
                  AND (window_start IS NULL OR window_start <= CURRENT_TIMESTAMP)
                  AND status = 0
                """, Long.class);
        for (Long id : ids) {
            try {
                dispatchApproved(id);
            } catch (Exception e) {
                log.error("窗口派发失败: task={}", id, e);
            }
        }
    }

    /** 派发已审批任务：按 targets 分组下发 CmdVulnFix（PACKAGE 项） */
    private void dispatchApproved(long taskId) {
        Map<String, Object> task = jdbc.queryForMap(
                "SELECT CAST(targets AS TEXT) AS targets FROM t_fix_task WHERE id = ?", taskId);
        List<Map<String, Object>> targets = JsonUtils.read((String) task.get("targets"), List.class);
        Map<String, List<FixItem>> byAgent = new LinkedHashMap<>();
        for (Map<String, Object> t : targets) {
            Map<String, Object> payload = JsonUtils.read((String) t.get("fix_payload"), Map.class);
            byAgent.computeIfAbsent(String.valueOf(t.get("agent_id")), k -> new ArrayList<>())
                    .add(FixItem.newBuilder()
                            .setRefId(String.valueOf(t.get("ref_id")))
                            .setType(FixItem.FixType.PACKAGE)
                            .setPayload((String) t.get("fix_payload"))
                            .build());
            if (payload != null) {
                // payload 仅用于构造，无需额外处理
            }
        }
        jdbc.update("UPDATE t_fix_task SET status = 1, started_at = CURRENT_TIMESTAMP, dispatched_at = CURRENT_TIMESTAMP "
                + "WHERE id = ? AND dispatched_at IS NULL", taskId);
        for (var e : byAgent.entrySet()) {
            commandService.dispatch(e.getKey(), Command.newBuilder()
                    .setVulnFix(CmdVulnFix.newBuilder()
                            .setTaskId(String.valueOf(taskId))
                            .addAllFixes(e.getValue())), null);
        }
        log.info("软件包修复任务已派发: task_id={} agents={}", taskId, byAgent.size());
    }

    private static OffsetDateTime parseTime(String s) {
        if (s == null || s.isBlank()) {
            return null;
        }
        return OffsetDateTime.parse(s.contains("+") || s.endsWith("Z") ? s : s + ":00+08:00");
    }

    private static boolean isTrue(Object value) {
        return value instanceof Boolean bool ? bool
                : value instanceof Number number && number.intValue() != 0;
    }
}
