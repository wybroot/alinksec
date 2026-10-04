package com.alinksec.service.baseline;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.RptBaselineResult;
import com.alinksec.service.config.DatabaseDialect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

/**
 * 基线核查结果落库（docs/04 §4.3）：
 * 明细幂等替换（task+agent 维度先删后插）→ 汇总 upsert → 任务进度/状态推进。
 */
@Service
public class BaselineResultService {

    private static final Logger log = LoggerFactory.getLogger(BaselineResultService.class);

    private final JdbcTemplate jdbc;

    public BaselineResultService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Transactional
    public void onResult(String agentId, RptBaselineResult result) {
        long taskId;
        try {
            taskId = Long.parseLong(result.getTaskId().trim());
        } catch (NumberFormatException e) {
            log.warn("基线结果 task_id 非法: agent={} task_id={}", agentId, result.getTaskId());
            return;
        }
        if (taskId <= 0 || result.getItemsCount() == 0 || result.getItemsCount() > 500) {
            log.warn("基线结果任务或检查项数量非法: agent={} task={}", agentId, taskId); return;
        }
        for (var item : result.getItemsList()) {
            String outcome = item.getExecutionStatus();
            if (!List.of("", "pass", "fail", "error").contains(outcome)
                    || !outcome.isEmpty() && item.getPassed() != outcome.equals("pass")) {
                log.warn("基线结果状态与通过标记不一致: agent={} task={}", agentId, taskId); return;
            }
        }
        // Hold the task row until the report and progress commit. PostgreSQL
        // otherwise lets different Agents calculate progress from stale counts.
        var taskRows = jdbc.queryForList("UPDATE t_baseline_task SET progress=progress WHERE id=? RETURNING status,CAST(scope AS TEXT) AS scope", taskId);
        if (taskRows.isEmpty()) {
            log.warn("基线结果指向不存在的任务: agent={} task_id={}", agentId, taskId);
            return;
        }
        int status = ((Number) taskRows.get(0).get("status")).intValue();
        if (status == 4) { // 已取消
            log.info("任务已取消，结果丢弃: agent={} task_id={}", agentId, taskId);
            return;
        }

        // New tasks accept one complete result for exactly the checks sent to this Agent.
        int expectedTask = jdbc.queryForObject("SELECT count(*) FROM t_baseline_task_expected WHERE task_id=?", Integer.class, taskId);
        if (expectedTask > 0) {
            var expected = new java.util.HashSet<>(jdbc.queryForList("SELECT item_id FROM t_baseline_task_expected WHERE task_id=? AND agent_id=?", Long.class, taskId, agentId));
            var actual = new java.util.HashSet<Long>();
            boolean invalid = expected.isEmpty();
            for (var item : result.getItemsList()) {
                try { if (!actual.add(Long.parseLong(item.getItemId()))) invalid = true; }
                catch (NumberFormatException e) { invalid = true; }
            }
            if (invalid || !expected.equals(actual)) {
                log.warn("拒绝不完整、重复或越权的基线结果: agent={} task={}", agentId, taskId); return;
            }
            if (jdbc.queryForObject("SELECT count(*) FROM t_baseline_summary WHERE task_id=? AND agent_id=?", Integer.class, taskId, agentId) > 0) {
                // The first complete report is evidence. Retries cannot replace
                // the results an administrator already reviewed or published.
                log.info("基线结果已接受，重复回报保持原证据: agent={} task={}", agentId, taskId); return;
            }
        } else {
            var scope = JsonUtils.read(String.valueOf(taskRows.get(0).get("scope")));
            boolean allowed = false;
            for (var target : scope.path("agent_ids")) if (agentId.equals(target.asText())) allowed = true;
            if (!allowed) { log.warn("基线结果主机不在任务范围: agent={} task={}", agentId, taskId); return; }
        }

        // 明细幂等替换（Agent 重试/离线补传重复上报）
        jdbc.update("DELETE FROM t_baseline_result WHERE task_id = ? AND agent_id = ?", taskId, agentId);
        List<Object[]> rows = new ArrayList<>();
        int passed = 0, errors = 0, legacy = 0;
        for (var item : result.getItemsList()) {
            long itemId;
            try {
                itemId = Long.parseLong(item.getItemId().trim());
            } catch (NumberFormatException e) {
                log.warn("基线结果 item_id 非法: agent={} task={} item={}",
                        agentId, taskId, item.getItemId());
                continue;
            }
            String outcome = item.getExecutionStatus().isEmpty() ? "legacy" : item.getExecutionStatus();
            if (outcome.equals("error")) errors++;
            if (outcome.equals("legacy")) legacy++;
            rows.add(new Object[]{taskId, agentId, itemId, item.getPassed(), bounded(item.getActual(), 4096), bounded(item.getMessage(), 2048), outcome, Integer.toUnsignedLong(item.getDurationMs())});
            if (item.getPassed()) {
                passed++;
            }
        }
        if (!rows.isEmpty()) {
            jdbc.batchUpdate("""
                    INSERT INTO t_baseline_result (task_id, agent_id, item_id, passed, actual, message, execution_status, duration_ms, checked_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """, rows);
        }
        int total = rows.size();
        int failed = total - passed;
        int score = total == 0 ? 0 : (int) Math.round(passed * 100.0 / total);
        jdbc.update("""
                INSERT INTO t_baseline_summary (task_id, agent_id, total, passed_count, failed_count, score, error_count, legacy_count, checked_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT (task_id, agent_id) DO UPDATE
                SET total = EXCLUDED.total, passed_count = EXCLUDED.passed_count,
                    failed_count = EXCLUDED.failed_count, score = EXCLUDED.score,
                    error_count=EXCLUDED.error_count, legacy_count=EXCLUDED.legacy_count, checked_at = CURRENT_TIMESTAMP
                """, taskId, agentId, total, passed, failed, score, errors, legacy);

        updateTaskProgress(taskId);
        log.info("基线结果已落库: agent={} task={} total={} failed={}", agentId, taskId, total, failed);
    }

    private static String bounded(String value, int limit) {
        if (value.length() <= limit) return value;
        int end = limit;
        if (Character.isHighSurrogate(value.charAt(end - 1))) end--;
        return value.substring(0, end) + "…";
    }

    /** 进度 = 已上报主机数 / scope 主机数；全部收齐 → 完成 */
    private void updateTaskProgress(long taskId) {
        String scope = jdbc.queryForObject(
                "SELECT CAST(scope AS TEXT) FROM t_baseline_task WHERE id = ?", String.class, taskId);
        var scopeJson = JsonUtils.read(scope == null ? "{}" : scope);
        List<Object> targets = new ArrayList<>();
        List<String> conditions = new ArrayList<>();
        var agentIds = scopeJson.path("agent_ids");
        if (agentIds.isArray() && !agentIds.isEmpty()) {
            conditions.add("a.agent_id IN (" + DatabaseDialect.placeholders(agentIds.size()) + ")");
            agentIds.forEach(value -> targets.add(value.asText()));
        }
        var groupIds = scopeJson.path("group_ids");
        if (groupIds.isArray() && !groupIds.isEmpty()) {
            conditions.add("a.group_id IN (" + DatabaseDialect.placeholders(groupIds.size()) + ")");
            groupIds.forEach(value -> targets.add(value.asLong()));
        }
        Integer agentCount = conditions.isEmpty() ? 0 : jdbc.queryForObject(
                "SELECT count(*) FROM t_agent a WHERE " + String.join(" OR ", conditions),
                Integer.class, targets.toArray());
        Integer reported = jdbc.queryForObject(
                "SELECT count(*) FROM t_baseline_summary WHERE task_id = ?", Integer.class, taskId);
        Integer capturedCount = jdbc.queryForObject("SELECT count(DISTINCT agent_id) FROM t_baseline_task_expected WHERE task_id=?", Integer.class, taskId);
        int total = capturedCount != null && capturedCount > 0 ? capturedCount : agentCount == null ? 0 : agentCount;
        int done = reported == null ? 0 : reported;
        int progress = total == 0 ? 100 : Math.min(100, done * 100 / total);
        if (done >= total && total > 0) {
            jdbc.update("UPDATE t_baseline_task SET progress = ?, status = 2, finished_at = CURRENT_TIMESTAMP WHERE id = ?",
                    progress, taskId);
        } else {
            jdbc.update("""
                    UPDATE t_baseline_task SET progress = ?, status = CASE WHEN status=3 THEN 3 ELSE 1 END,
                           started_at = COALESCE(started_at, CURRENT_TIMESTAMP),
                           finished_at = CASE WHEN status=3 THEN finished_at ELSE NULL END
                    WHERE id = ? AND status IN (0, 1, 3)
                    """, progress, taskId);
        }
    }
}
