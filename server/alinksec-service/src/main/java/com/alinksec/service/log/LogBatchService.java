package com.alinksec.service.log;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.LogLine;
import com.alinksec.proto.RptLogBatch;
import com.alinksec.service.config.DatabaseDialect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.time.Duration;

/**
 * LOG_BATCH 落库（t_agent_log）：登录/安全日志，供排障与入侵检测回溯。
 * 保留 30 天（凌晨定时清理）。
 */
@Service
public class LogBatchService {

    private static final Logger log = LoggerFactory.getLogger(LogBatchService.class);
    private static final int MAX_LINES = 500; // 单批落库上限（防异常大包打爆 PG）

    private final JdbcTemplate jdbc;
    private final DatabaseDialect database;

    public LogBatchService(JdbcTemplate jdbc, DatabaseDialect database) {
        this.jdbc = jdbc;
        this.database = database;
    }

    @Transactional
    public void onBatch(String agentId, RptLogBatch batch) {
        List<LogLine> lines = batch.getLinesList();
        if (lines.isEmpty()) {
            return;
        }
        if (lines.size() > MAX_LINES) {
            lines = lines.subList(0, MAX_LINES);
        }
        String source = truncate(batch.getSource(), 64);
        List<Object[]> rows = new ArrayList<>(lines.size());
        for (LogLine l : lines) {
            String fields = l.getFieldsCount() == 0 ? null : JsonUtils.write(l.getFieldsMap());
            rows.add(new Object[]{agentId, source, truncate(l.getContent(), 4000),
                    fields, l.getTs()});
        }
        jdbc.batchUpdate("""
                INSERT INTO t_agent_log (agent_id, source, content, fields, log_ts)
                VALUES (?, ?, ?, ?, ?)
                """, rows);
        log.debug("日志批次落库: agent={} source={} lines={}", agentId, source, rows.size());
    }

    /** 每日凌晨 3:20 清理 30 天前日志 */
    @Scheduled(cron = "0 20 3 * * *")
    public void cleanup() {
        int rows = jdbc.update("DELETE FROM t_agent_log WHERE created_at < ?",
                database.timestampBefore(Duration.ofDays(30)));
        if (rows > 0) {
            log.info("清理过期 Agent 日志: {} 行", rows);
        }
    }

    private static String truncate(String s, int max) {
        if (s == null) {
            return "";
        }
        return s.length() > max ? s.substring(0, max) : s;
    }
}
