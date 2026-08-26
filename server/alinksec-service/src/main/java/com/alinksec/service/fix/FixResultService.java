package com.alinksec.service.fix;

import com.alinksec.proto.FixResultItem;
import com.alinksec.proto.RptFixResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 修复结果落库（docs/05 §3）：RptFixResult → t_fix_record 状态更新 + t_fix_task 汇总。
 *
 * 状态映射（t_fix_record.status）：
 *   success=true → 1 成功（verified 由 Agent 复核后置位）
 *   success=false & rolled_back=true → 2 失败已回滚
 *   success=false & rolled_back=false → 3 失败未回滚（需人工检查）
 */
@Service
public class FixResultService {

    private static final Logger log = LoggerFactory.getLogger(FixResultService.class);

    private final JdbcTemplate jdbc;

    public FixResultService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Transactional
    public void onResult(String agentId, RptFixResult result) {
        long taskId;
        try {
            taskId = Long.parseLong(result.getTaskId());
        } catch (NumberFormatException e) {
            log.warn("修复结果 task_id 非法: {} agent={}", result.getTaskId(), agentId);
            return;
        }
        for (FixResultItem item : result.getResultsList()) {
            int status = item.getSuccess() ? 1 : (item.getRolledBack() ? 2 : 3);
            int updated = jdbc.update("""
                    UPDATE t_fix_record SET status = ?, log = ?, finished_at = now()
                    WHERE task_id = ? AND agent_id = ? AND ref_id = ?
                    """, status, truncate(item.getLog()), taskId, agentId, item.getRefId());
            if (updated == 0) {
                // 兼容任务外单条补报（正常不出现）：补插记录
                jdbc.update("""
                        INSERT INTO t_fix_record (task_id, agent_id, ref_id, ref_type, status, log, finished_at)
                        VALUES (?, ?, ?, 'baseline_item', ?, ?, now())
                        """, taskId, agentId, item.getRefId(), status, truncate(item.getLog()));
            }
            // 软件包类（ref_type=vuln_finding）修复成功 → 漏洞清单置已修复（docs/05 §3.3）
            if (item.getSuccess()) {
                jdbc.update("""
                        UPDATE t_vuln_finding SET status = 3
                        WHERE id = ?::bigint AND agent_id = ?
                          AND EXISTS (SELECT 1 FROM t_fix_record r
                                      WHERE r.task_id = ? AND r.agent_id = ? AND r.ref_id = ?::varchar
                                        AND r.ref_type = 'vuln_finding')
                        """, item.getRefId(), agentId, taskId, agentId, item.getRefId());
            }
        }
        refreshTaskStatus(taskId);
        log.info("修复结果已落库: task={} agent={} items={}", taskId, agentId, result.getResultsCount());
    }

    /** 汇总任务状态：全部 record 到终态 → 2 完成 / 3 部分失败 */
    private void refreshTaskStatus(long taskId) {
        Integer pending = jdbc.queryForObject(
                "SELECT count(*) FROM t_fix_record WHERE task_id = ? AND status = 0", Integer.class, taskId);
        if (pending != null && pending > 0) {
            return; // 仍有主机未回传
        }
        Integer failed = jdbc.queryForObject(
                "SELECT count(*) FROM t_fix_record WHERE task_id = ? AND status IN (2,3,5)", Integer.class, taskId);
        jdbc.update("""
                UPDATE t_fix_task SET status = ?, finished_at = now()
                WHERE id = ? AND status = 1
                """, failed != null && failed > 0 ? 3 : 2, taskId);
    }

    private static String truncate(String s) {
        if (s == null) return null;
        return s.length() > 8000 ? s.substring(0, 8000) : s;
    }
}
