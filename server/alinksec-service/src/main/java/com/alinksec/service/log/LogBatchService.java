package com.alinksec.service.log;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.*;
import com.alinksec.service.config.DatabaseDialect;
import com.alinksec.service.evidence.EvidenceService;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;

/** Whole batches are validated before mutation. Capacity, deduplication and
 * retention accounting share the caller's business transaction. */
@Service
public class LogBatchService {
    public static final int MAX_LINES=100, MAX_CONTENT_BYTES=65536, MAX_FIELDS_BYTES=8192, MAX_BATCH_BYTES=1<<20;
    public static final long MAX_ROWS=200000, MAX_STORED_BYTES=1L<<30;
    private final JdbcTemplate jdbc;
    private final DatabaseDialect database;
    public LogBatchService(JdbcTemplate jdbc,DatabaseDialect database) {this.jdbc=jdbc;this.database=database;}
    public static int bytes(String s){return s.getBytes(StandardCharsets.UTF_8).length;}
    public static String sha(String s){return EvidenceService.sha(s.getBytes(StandardCharsets.UTF_8));}
    private record Row(String content,String fields,long ts,String key,String digest,String kind,int bytes){}
    public static void gate(JdbcTemplate jdbc) {
        if(jdbc.update("UPDATE t_agent_log_state SET retained_rows=retained_rows WHERE id=1")!=1)
            throw new IllegalStateException("日志容量状态不存在");
    }
    /** Compatibility for internal callers without report identity; wire reports always supply it. */
    @Transactional public void onBatch(String agent,RptLogBatch batch) {onBatch(agent,UUID.randomUUID().toString(),batch);}
    @Transactional public void onBatch(String agent,String reportId,RptLogBatch batch) {
        if(agent==null || agent.isBlank() || agent.length()>64 || reportId==null || reportId.isBlank() || reportId.length()>128
                || batch==null || batch.getLinesCount()>MAX_LINES || batch.getSerializedSize()>MAX_BATCH_BYTES)
            throw new IllegalArgumentException("日志批次身份、行数或大小无效");
        String source=batch.getSource();
        if(source.isBlank() || bytes(source)>64 || source.codePoints().anyMatch(Character::isISOControl))
            throw new IllegalArgumentException("日志来源无效");
        List<Row> rows=new ArrayList<>();int index=0;
        for(LogLine line:batch.getLinesList()) {
            String raw=line.getContent(),fields=JsonUtils.write(line.getFieldsMap());
            if(bytes(raw)>MAX_CONTENT_BYTES || raw.indexOf(0)>=0 || line.getFieldsCount()>32 || bytes(fields)>MAX_FIELDS_BYTES
                    || line.getTs()<0 || line.getTs()>4102444800000L
                    || line.getFieldsMap().entrySet().stream().anyMatch(e->e.getKey().isBlank() || bytes(e.getKey())>128 || bytes(e.getValue())>4096 || (e.getKey()+e.getValue()).indexOf(0)>=0))
                throw new IllegalArgumentException("日志行、字段或时间超出范围");
            String key=line.getFieldsOrDefault("source_event_id","");
            if(key.isEmpty())key=sha(reportId+"\u0000"+index);
            if(!key.matches("[a-f0-9]{64}"))throw new IllegalArgumentException("日志事件标识无效");
            String kind=line.getFieldsOrDefault("timestamp_kind","legacy_unknown");
            if(!Set.of("observed","event","legacy_unknown").contains(kind))throw new IllegalArgumentException("日志时间语义无效");
            rows.add(new Row(raw,fields,line.getTs(),key,sha(raw),kind,bytes(raw)+bytes(fields)+256));index++;
        }
        if(rows.isEmpty())return;
        gate(jdbc);
        var state=jdbc.queryForMap("SELECT retained_rows,retained_bytes FROM t_agent_log_state WHERE id=1");
        long count=((Number)state.get("retained_rows")).longValue(),size=((Number)state.get("retained_bytes")).longValue();
        for(Row row:rows) {
            var existing=jdbc.queryForList("SELECT content_sha256 FROM t_agent_log WHERE agent_id=? AND source=? AND event_key=?",String.class,agent,source,row.key());
            if(!existing.isEmpty()) {
                if(!existing.getFirst().equals(row.digest()))throw new IllegalArgumentException("同一日志身份的原文发生变化");
                continue;
            }
            if(count+1>MAX_ROWS || size+row.bytes()>MAX_STORED_BYTES)throw new IllegalArgumentException("日志存储已达到容量上限，请清理保留记录");
            String preview=row.content().substring(0,Math.min(4000,row.content().length()));
            if(!preview.isEmpty() && Character.isHighSurrogate(preview.charAt(preview.length()-1)))preview=preview.substring(0,preview.length()-1);
            jdbc.update("INSERT INTO t_agent_log(agent_id,source,content,raw_content,fields,log_ts,event_key,content_sha256,time_kind,stored_bytes) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    agent,source,preview,row.content(),row.fields(),row.ts(),row.key(),row.digest(),row.kind(),row.bytes());
            count++;size+=row.bytes();
        }
        jdbc.update("UPDATE t_agent_log_state SET retained_rows=?,retained_bytes=? WHERE id=1",count,size);
    }
    /** Small, independently committed batches keep live intake available. */
    @Scheduled(fixedDelay=60000,initialDelay=60000)
    @Transactional public void cleanup() {cleanupBefore(database.timestampBefore(Duration.ofDays(30)));}
    public int cleanupBefore(Object cutoff) {
        gate(jdbc);
        var rows=jdbc.queryForList("SELECT id,stored_bytes FROM t_agent_log WHERE "+(database.isSqlite()?"julianday(created_at)<julianday(?)":"created_at<?")+" ORDER BY created_at,id LIMIT 500",cutoff);
        if(rows.isEmpty())return 0;
        long size=rows.stream().mapToLong(r->((Number)r.get("stored_bytes")).longValue()).sum();
        var ids=rows.stream().map(r->r.get("id")).toArray();
        jdbc.update("DELETE FROM t_agent_log WHERE id IN ("+DatabaseDialect.placeholders(ids.length)+")",ids);
        jdbc.update("UPDATE t_agent_log_state SET retained_rows=retained_rows-?,retained_bytes=retained_bytes-? WHERE id=1",ids.length,size);
        return ids.length;
    }
}
