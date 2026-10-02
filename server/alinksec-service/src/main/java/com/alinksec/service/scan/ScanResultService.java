package com.alinksec.service.scan;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.RptScanResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

/**
 * 安全扫描结果落库（Agent RptScanResult → t_weakpwd_finding / t_port_finding）。
 *
 * 幂等：同一 task+agent 结果先删后插（指令重推导致的重复上报安全）。
 * 进度：按 scope 主机数累加，收齐即置完成。
 */
@Service
public class ScanResultService {

    private static final Logger log = LoggerFactory.getLogger(ScanResultService.class);

    private final JdbcTemplate jdbc;

    public ScanResultService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Transactional
    public void onResult(String agentId, RptScanResult result) {
        long taskId;
        try {
            taskId = Long.parseLong(result.getTaskId());
        } catch (NumberFormatException e) {
            log.warn("扫描结果 task_id 非法，仅落库: agent={} task_id={}", agentId, result.getTaskId());
            taskId = 0;
        }

        // 弱口令发现（任务维度先删后插，重放安全）
        if (result.getWeakPasswordsCount() > 0) {
            jdbc.update("DELETE FROM t_weakpwd_finding WHERE task_id = ? AND agent_id = ?",
                    taskId, agentId);
            for (var w : result.getWeakPasswordsList()) {
                jdbc.update("""
                        INSERT INTO t_weakpwd_finding (task_id, agent_id, account, type, remark, status)
                        VALUES (?, ?, ?, ?, ?, 0)
                        """, taskId, agentId, w.getAccount(), w.getType(),
                        w.getPassword().isBlank() ? null : w.getPassword());
            }
        }
        // 端口服务发现
        if (result.getPortServicesCount() > 0) {
            jdbc.update("DELETE FROM t_port_finding WHERE task_id = ? AND agent_id = ?",
                    taskId, agentId);
            for (var p : result.getPortServicesList()) {
                jdbc.update("""
                        INSERT INTO t_port_finding
                          (task_id, agent_id, port, protocol, process, service, risky, risky_reason)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """, taskId, agentId, p.getPort(), p.getProtocol(), p.getProcess(),
                        p.getService(), p.getRisky(),
                        p.getRiskyReason().isBlank() ? null : p.getRiskyReason());
            }
        }
        advanceProgress(taskId, agentId);
        log.info("扫描结果已落库: agent={} task={} weak_pwd={} ports={}",
                agentId, taskId, result.getWeakPasswordsCount(), result.getPortServicesCount());
    }

    /** 进度按 scope 主机数累加：每台主机首次结果 +ceil(100/N)，达 100 置完成 */
    private void advanceProgress(long taskId, String agentId) {
        List<Map<String, Object>> rows = taskId > 0
                ? jdbc.queryForList("SELECT CAST(scope AS TEXT) AS scope FROM t_scan_task WHERE id = ?", taskId)
                : List.of();
        if (rows.isEmpty()) {
            return; // 任务行不存在（数据被清理）：只落库不推进
        }
        var agents = JsonUtils.read((String) rows.get(0).get("scope")).path("agent_ids");
        int total = agents.isArray() ? agents.size() : 0;
        if (total <= 0) {
            return;
        }
        int step = (int) Math.ceil(100.0 / total);
        jdbc.update("""
                UPDATE t_scan_task
                SET progress = CASE WHEN progress + ? >= 100 THEN 100 ELSE progress + ? END,
                    status = CASE WHEN progress + ? >= 100 THEN 2 ELSE 1 END,
                    finished_at = CASE WHEN progress + ? >= 100 THEN CURRENT_TIMESTAMP ELSE finished_at END
                WHERE id = ? AND status = 1
                """, step, step, step, step, taskId);
    }
}
