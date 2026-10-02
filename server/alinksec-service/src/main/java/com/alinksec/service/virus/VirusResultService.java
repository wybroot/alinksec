package com.alinksec.service.virus;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.RptVirusResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 病毒扫描结果落库（Agent RptVirusResult → t_virus_finding）。
 *
 * 白名单过滤（docs/05 §1.4：平台全局生效）：hash 精确 / path 前缀匹配的命中不上报入库。
 * 幂等：同 task+agent 结果先删后插（指令重推重复上报安全）。
 * 进度：按 scope 主机数推进，收齐置完成。
 */
@Service
public class VirusResultService {

    private static final Logger log = LoggerFactory.getLogger(VirusResultService.class);

    private final JdbcTemplate jdbc;

    public VirusResultService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Transactional
    public void onResult(String agentId, RptVirusResult result) {
        long taskId;
        try {
            taskId = Long.parseLong(result.getTaskId());
        } catch (NumberFormatException e) {
            log.warn("病毒结果 task_id 非法，仅落库: agent={} task_id={}", agentId, result.getTaskId());
            taskId = 0;
        }

        Set<String> wlHashes = new HashSet<>();
        List<String> wlPaths = new java.util.ArrayList<>();
        jdbc.query("SELECT type, value FROM t_virus_whitelist", (rs) -> {
            if ("hash".equals(rs.getString(1))) {
                wlHashes.add(rs.getString(2).toLowerCase());
            } else {
                wlPaths.add(rs.getString(2));
            }
        });

        jdbc.update("DELETE FROM t_virus_finding WHERE task_id = ? AND agent_id = ?", taskId, agentId);
        int inserted = 0;
        for (var f : result.getFindingsList()) {
            if (wlHashes.contains(f.getSha256().toLowerCase())) {
                continue;
            }
            if (matchesPathWhitelist(f.getPath(), wlPaths)) {
                continue;
            }
            String action = f.getActionTaken().isBlank() ? "alert_only" : f.getActionTaken();
            jdbc.update("""
                    INSERT INTO t_virus_finding
                      (task_id, agent_id, path, name, sha256, size, engine, severity, action_taken, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, taskId, agentId, f.getPath(), f.getName(), f.getSha256(),
                    f.getSize(), f.getEngine(), f.getSeverity().getNumber(), action,
                    "quarantined".equals(action) ? 1 : 0);
            inserted++;
        }
        advanceProgress(taskId, agentId);
        log.info("病毒结果已落库: agent={} task={} files={} findings={} kept={}",
                agentId, taskId, result.getFilesScanned(), result.getFindingsCount(), inserted);
    }

    /** 白名单 path 语义：值即路径或其父目录前缀（目录加白 → 目录下全部放行） */
    private static boolean matchesPathWhitelist(String path, List<String> prefixes) {
        for (String p : prefixes) {
            String norm = p.endsWith("/") || p.endsWith("\\") ? p : p + "/";
            if (path.equals(p) || path.startsWith(norm) || path.replace('\\', '/').startsWith(norm)) {
                return true;
            }
        }
        return false;
    }

    /** 进度按 scope 主机数推进（同 ScanResultService 语义） */
    private void advanceProgress(long taskId, String agentId) {
        if (taskId <= 0) {
            return;
        }
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT CAST(scope AS TEXT) AS scope FROM t_virus_scan_task WHERE id = ?", taskId);
        if (rows.isEmpty()) {
            return;
        }
        var agents = JsonUtils.read((String) rows.get(0).get("scope")).path("agent_ids");
        int total = agents.isArray() ? agents.size() : 0;
        if (total <= 0) {
            return;
        }
        int step = (int) Math.ceil(100.0 / total);
        jdbc.update("""
                UPDATE t_virus_scan_task
                SET progress = CASE WHEN progress + ? >= 100 THEN 100 ELSE progress + ? END,
                    status = CASE WHEN progress + ? >= 100 THEN 2 ELSE 1 END,
                    finished_at = CASE WHEN progress + ? >= 100 THEN CURRENT_TIMESTAMP ELSE finished_at END
                WHERE id = ? AND status = 1
                """, step, step, step, step, taskId);
    }
}
