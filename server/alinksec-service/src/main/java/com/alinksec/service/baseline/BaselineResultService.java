package com.alinksec.service.baseline;

import com.alinksec.proto.RptBaselineResult;
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
        Integer status = jdbc.queryForObject(
                "SELECT status FROM t_baseline_task WHERE id = ?", Integer.class, taskId);
        if (status == null) {
            log.warn("基线结果指向不存在的任务: agent={} task_id={}", agentId, taskId);
            return;
        }
        if (status == 4) { // 已取消
            log.info("任务已取消，结果丢弃: agent={} task_id={}", agentId, taskId);
            return;
        }

        // 明细幂等替换（Agent 重试/离线补传重复上报）
        jdbc.update("DELETE FROM t_baseline_result WHERE task_id = ? AND agent_id = ?", taskId, agentId);
        List<Object[]> rows = new ArrayList<>();
        int passed = 0;
        for (var item : result.getItemsList()) {
            long itemId;
            try {
                itemId = Long.parseLong(item.getItemId().trim());
            } catch (NumberFormatException e) {
                log.warn("基线结果 item_id 非法: agent={} task={} item={}",
                        agentId, taskId, item.getItemId());
                continue;
            }
            rows.add(new Object[]{taskId, agentId, itemId, item.getPassed(), item.getActual(), item.getMessage()});
            if (item.getPassed()) {
                passed++;
            }
        }
        if (!rows.isEmpty()) {
            jdbc.batchUpdate("""
                    INSERT INTO t_baseline_result (task_id, agent_id, item_id, passed, actual, message, checked_at)
                    VALUES (?, ?, ?, ?, ?, ?, now())
                    """, rows);
        }
        int total = rows.size();
        int failed = total - passed;
        int score = total == 0 ? 0 : (int) Math.round(passed * 100.0 / total);
        jdbc.update("""
                INSERT INTO t_baseline_summary (task_id, agent_id, total, passed_count, failed_count, score, checked_at)
                VALUES (?, ?, ?, ?, ?, ?, now())
                ON CONFLICT (task_id, agent_id) DO UPDATE
                SET total = EXCLUDED.total, passed_count = EXCLUDED.passed_count,
                    failed_count = EXCLUDED.failed_count, score = EXCLUDED.score, checked_at = now()
                """, taskId, agentId, total, passed, failed, score);

        updateTaskProgress(taskId);
        log.info("基线结果已落库: agent={} task={} total={} failed={}", agentId, taskId, total, failed);
    }

    /** 进度 = 已上报主机数 / scope 主机数；全部收齐 → 完成 */
    private void updateTaskProgress(long taskId) {
        Integer agentCount = jdbc.queryForObject("""
                SELECT count(*) FROM t_agent a
                WHERE a.agent_id = ANY (SELECT jsonb_array_elements_text(t.scope->'agent_ids')
                                        FROM t_baseline_task t WHERE t.id = ?)
                   OR a.group_id IN (SELECT (jsonb_array_elements_text(t.scope->'group_ids'))::bigint
                                     FROM t_baseline_task t WHERE t.id = ?)
                """, Integer.class, taskId, taskId);
        Integer reported = jdbc.queryForObject(
                "SELECT count(*) FROM t_baseline_summary WHERE task_id = ?", Integer.class, taskId);
        int total = agentCount == null ? 0 : agentCount;
        int done = reported == null ? 0 : reported;
        int progress = total == 0 ? 100 : Math.min(100, done * 100 / total);
        if (done >= total && total > 0) {
            jdbc.update("UPDATE t_baseline_task SET progress = ?, status = 2, finished_at = now() WHERE id = ?",
                    progress, taskId);
        } else {
            jdbc.update("""
                    UPDATE t_baseline_task SET progress = ?, status = 1,
                           started_at = COALESCE(started_at, now()), finished_at = NULL
                    WHERE id = ? AND status IN (0, 1, 3)
                    """, progress, taskId);
        }
    }
}
