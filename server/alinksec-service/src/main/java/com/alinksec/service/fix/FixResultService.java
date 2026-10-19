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
        jdbc.update("UPDATE t_fix_task SET status=status WHERE id=?",taskId);
        jdbc.update("UPDATE t_agent SET software_revision=software_revision WHERE agent_id=?",agentId);
        for (FixResultItem item : result.getResultsList()) {
            if(WindowsUpdateResult.accept(jdbc,agentId,taskId,item)) continue;
            int status = item.getSuccess() ? 1 : (item.getRolledBack() ? 2 : 3);
            boolean unverifiedSuccess = item.getSuccess() && !item.getVerified();
            int updated = jdbc.update("""
                    UPDATE t_fix_record SET reboot_required=?,verified=?,status = CASE WHEN ref_type='vuln_finding' AND ? THEN 3 ELSE ? END,
                      log = CASE WHEN ref_type='vuln_finding' AND ? THEN ? ELSE ? END, finished_at = CURRENT_TIMESTAMP
                    WHERE task_id = ? AND agent_id = ? AND ref_id = ? AND status = 0
                      AND EXISTS (SELECT 1 FROM t_fix_task t WHERE t.id = ? AND t.status = 1)
                      AND (ref_type <> 'vuln_finding' OR EXISTS (
                        SELECT 1 FROM t_command c WHERE c.cmd_id=t_fix_record.command_id
                          AND c.agent_id=t_fix_record.agent_id AND c.status IN (1,2,3,4)))
                    """,item.getRebootRequired()?1:0,item.getVerified()?1:0, unverifiedSuccess, status, unverifiedSuccess,
                    truncate("未确认安装后身份及完整版本，不标记漏洞已修复。\n" + item.getLog()), truncate(item.getLog()),
                    taskId, agentId, item.getRefId(), taskId);
            if (updated == 0) {
                log.warn("忽略未下发、越权或重复的修复结果: task={} agent={} ref={}",
                        taskId, agentId, item.getRefId());
                continue;
            }
            // 软件包类（ref_type=vuln_finding）修复成功 → 漏洞清单置已修复（docs/05 §3.3）
            String refType = jdbc.queryForObject("""
                    SELECT ref_type FROM t_fix_record WHERE task_id = ? AND agent_id = ? AND ref_id = ?
                    """, String.class, taskId, agentId, item.getRefId());
            if (item.getSuccess() && item.getVerified() && "vuln_finding".equals(refType)) {
                jdbc.update("""
                        UPDATE t_vuln_finding SET status = 3,resolved_inventory_revision=(SELECT software_revision FROM t_agent WHERE agent_id=?)
                        WHERE id = CAST(? AS BIGINT) AND agent_id = ?
                          AND EXISTS (SELECT 1 FROM t_fix_record r
                                      WHERE r.task_id = ? AND r.agent_id = ? AND r.ref_id = CAST(? AS TEXT)
                                        AND r.ref_type = 'vuln_finding')
                        """, agentId,item.getRefId(), agentId, taskId, agentId, item.getRefId());
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
                "SELECT count(*) FROM t_fix_record WHERE task_id = ? AND status IN (2,3,5,8)", Integer.class, taskId);
        Integer reboot=jdbc.queryForObject("SELECT count(*) FROM t_fix_record WHERE task_id=? AND status IN (6,7)",Integer.class,taskId);
        jdbc.update("""
                UPDATE t_fix_task SET status = ?, finished_at = CURRENT_TIMESTAMP
                WHERE id = ? AND status IN (1,3,5)
                """, reboot!=null && reboot>0 ? 5 : failed != null && failed > 0 ? 3 : 2, taskId);
    }

    private static String truncate(String s) {
        if (s == null) return null;
        return s.length() > 8000 ? s.substring(0, 8000) : s;
    }
}
