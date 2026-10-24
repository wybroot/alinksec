package com.alinksec.service.log;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.config.DatabaseDialect;
import com.alinksec.service.evidence.EvidenceService;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;

/** Literal, case-sensitive raw-text search. Each request scans a bounded ID
 * interval and reports continuation explicitly; it never claims an exact total. */
@Service
public class LogSearchService {
    public static final int PAGE_SIZE=50,SCAN_IDS=5000,MAX_EXPORT_BYTES=8<<20;
    private static final String RAW="COALESCE(l.raw_content,l.content)";
    private final JdbcTemplate jdbc;
    private final DatabaseDialect database;
    private final TransactionTemplate tx;
    public LogSearchService(JdbcTemplate jdbc,DatabaseDialect database,PlatformTransactionManager manager) {
        this.jdbc=jdbc;this.database=database;this.tx=new TransactionTemplate(manager);tx.setTimeout(10);
    }
    public record Query(long from,long to,String agent,String source,String keyword,String cursor){}
    public record Export(List<String> ids,String format){}
    public record File(byte[] bytes,String sha256,String filename){}
    private record Cursor(long snapshot,long before,long floor,String query){}
    private static String text(String s,int max) {
        if(s==null)return "";
        if(s.length()>max || s.indexOf(0)>=0)throw new IllegalArgumentException("日志检索条件过长或包含无效字符");return s;
    }
    private Query checked(Query q) {
        if(q==null || q.from()<0 || q.to()<=q.from() || q.to()-q.from()>Duration.ofDays(31).toMillis()
                || q.to()>System.currentTimeMillis()+Duration.ofMinutes(5).toMillis())
            throw new IllegalArgumentException("请选择不超过 31 天的入库时间范围");
        return new Query(q.from(),q.to(),text(q.agent(),64),text(q.source(),64),text(q.keyword(),128),text(q.cursor(),1024));
    }
    private static String commitment(Query q){return LogBatchService.sha(JsonUtils.write(List.of(q.from(),q.to(),q.agent(),q.source(),q.keyword())));}
    private Cursor cursor(Query q) {
        if(q.cursor().isEmpty()) {
            long max=jdbc.queryForObject("SELECT COALESCE(MAX(id),0) FROM t_agent_log",Long.class);
            long min=jdbc.queryForObject("SELECT COALESCE(MIN(id),1) FROM t_agent_log",Long.class);
            if(max==Long.MAX_VALUE)throw new IllegalStateException("日志序号超出范围");
            return new Cursor(max,max+1,min,commitment(q));
        }
        try {
            var node=JsonUtils.read(new String(Base64.getUrlDecoder().decode(q.cursor()),StandardCharsets.UTF_8));
            var c=new Cursor(node.path("snapshot").longValue(),node.path("before").longValue(),node.path("floor").longValue(),node.path("query").asText());
            if(c.snapshot()<0 || c.snapshot()==Long.MAX_VALUE || c.before()<1 || c.before()>c.snapshot()+1 || c.floor()<1
                    || c.floor()>c.before() || !c.query().equals(commitment(q)))throw new IllegalArgumentException();
            return c;
        }catch(RuntimeException e){throw new IllegalArgumentException("日志游标与筛选条件不匹配，请重新检索");}
    }
    private static String encode(Cursor c){return Base64.getUrlEncoder().withoutPadding().encodeToString(JsonUtils.write(c).getBytes(StandardCharsets.UTF_8));}
    public Map<String,Object> search(Query input,Long actor) {
        Query q=checked(input);
        return tx.execute(s->{
            EvidenceService.admin(jdbc,actor);Cursor c=cursor(q);long lower=Math.max(c.floor(),Math.max(1,c.before()-SCAN_IDS));
            var args=new ArrayList<Object>(List.of(lower,c.before(),c.snapshot(),database.timestamp(Instant.ofEpochMilli(q.from())),database.timestamp(Instant.ofEpochMilli(q.to()))));
            var where=new StringBuilder(" WHERE l.id>=? AND l.id<? AND l.id<=?");
            where.append(database.isSqlite()?" AND julianday(l.created_at)>=julianday(?) AND julianday(l.created_at)<julianday(?)":" AND l.created_at>=? AND l.created_at<?");
            if(!q.agent().isEmpty()){where.append(" AND l.agent_id=?");args.add(q.agent());}
            if(!q.source().isEmpty()){where.append(" AND l.source=?");args.add(q.source());}
            if(!q.keyword().isEmpty()){where.append(database.isSqlite()?" AND instr("+RAW+",?)>0":" AND strpos("+RAW+",?)>0");args.add(q.keyword());}
            var rows=jdbc.queryForList("SELECT l.id,l.agent_id,l.source,l.log_ts,l.created_at,l.time_kind,l.content_sha256,l.fields,CASE WHEN l.raw_content IS NULL THEN 0 ELSE 1 END AS raw_available,SUBSTR("+RAW+",1,300) AS preview FROM t_agent_log l"+where+" ORDER BY l.id DESC LIMIT 51",args.toArray());
            boolean moreMatches=rows.size()>PAGE_SIZE;if(moreMatches)rows=new ArrayList<>(rows.subList(0,PAGE_SIZE));
            long before=moreMatches?((Number)rows.getLast().get("id")).longValue():lower;
            boolean complete=!moreMatches && lower<=c.floor();
            for(var row:rows)normalize(row);
            var result=new LinkedHashMap<String,Object>();result.put("items",rows);result.put("snapshot",String.valueOf(c.snapshot()));
            result.put("nextCursor",complete?null:encode(new Cursor(c.snapshot(),before,c.floor(),c.query())));
            result.put("scanComplete",complete);result.put("scanIdLimit",SCAN_IDS);result.put("pageSize",PAGE_SIZE);
            result.put("observedAt",System.currentTimeMillis());result.put("query",Map.of("from",q.from(),"to",q.to(),"agent",q.agent(),"source",q.source(),"keyword",q.keyword()));
            result.put("storage",jdbc.queryForMap("SELECT retained_rows,retained_bytes FROM t_agent_log_state WHERE id=1"));
            result.put("limits",Map.of("rows",LogBatchService.MAX_ROWS,"bytes",LogBatchService.MAX_STORED_BYTES,"retentionDays",30));
            return result;
        });
    }
    private void normalize(Map<String,Object> row) {
        row.put("id",row.get("id").toString());
        var at=database.readOffsetDateTime(row.get("created_at"));row.put("receivedAt",at==null?null:at.toInstant().toString());row.remove("created_at");
        Object raw=row.get("fields");row.put("fields",raw==null?Map.of():JsonUtils.read(raw.toString()));
        if(row.containsKey("raw_available"))row.put("raw_available",DatabaseDialect.readBoolean(row.get("raw_available")));
    }
    private static long id(String key) {
        try {if(key==null || !key.matches("[1-9][0-9]{0,18}"))throw new NumberFormatException();long n=Long.parseLong(key);if(n<1)throw new NumberFormatException();return n;}
        catch(NumberFormatException e){throw new IllegalArgumentException("日志编号无效");}
    }
    private Map<String,Object> load(long key) {
        var rows=jdbc.queryForList("SELECT l.id,l.agent_id,l.source,l.log_ts,l.created_at,l.time_kind,l.content_sha256,l.fields,CASE WHEN l.raw_content IS NULL THEN 0 ELSE 1 END AS raw_available,"+RAW+" AS content FROM t_agent_log l WHERE l.id=?",key);
        if(rows.size()!=1)throw new IllegalArgumentException("日志已过保留期或被清理，请重新检索");
        var row=rows.getFirst();normalize(row);
        if(row.get("content_sha256")!=null && !LogBatchService.sha(row.get("content").toString()).equals(row.get("content_sha256")))
            throw new IllegalStateException("日志原文摘要不匹配，暂时无法读取");
        return row;
    }
    public Map<String,Object> detail(String key,Long actor) {
        long value=id(key);return tx.execute(s->{EvidenceService.admin(jdbc,actor);return load(value);});
    }
    public File export(Export request,Long actor) {
        if(request==null || request.ids()==null || request.ids().isEmpty() || request.ids().size()>PAGE_SIZE
                || !Set.of("ndjson","csv").contains(request.format()==null?"":request.format()))throw new IllegalArgumentException("请选择当前页 1 至 50 条日志及导出格式");
        var keys=request.ids().stream().map(LogSearchService::id).distinct().sorted(Comparator.reverseOrder()).toList();
        if(keys.size()!=request.ids().size())throw new IllegalArgumentException("导出编号重复");
        return tx.execute(s->{
            EvidenceService.admin(jdbc,actor);var records=keys.stream().map(this::load).toList();StringBuilder out=new StringBuilder();
            if(request.format().equals("csv")) {
                out.append('\ufeff').append("id,agent_id,source,received_at,agent_time_ms,time_kind,raw_available,content_sha256,content,fields\r\n");
                for(var r:records) {
                    var cells=List.of(r.get("id"),r.get("agent_id"),r.get("source"),r.get("receivedAt"),r.get("log_ts"),r.get("time_kind"),r.get("raw_available"),Objects.toString(r.get("content_sha256"),""),r.get("content"),JsonUtils.write(r.get("fields")));
                    out.append(String.join(",",cells.stream().map(v->csv(v.toString())).toList())).append("\r\n");
                }
            }else for(var r:records)out.append(JsonUtils.write(r)).append('\n');
            byte[] bytes=out.toString().getBytes(StandardCharsets.UTF_8);
            if(bytes.length>MAX_EXPORT_BYTES)throw new IllegalArgumentException("当前导出超过 8 MiB，请减少条数");
            jdbc.update("INSERT INTO t_audit_log(uid,method,path,status,cost_ms) VALUES (?,'POST','/api/logs/export',200,0)",actor);
            return new File(bytes,EvidenceService.sha(bytes),"alinksec-logs."+(request.format().equals("csv")?"csv":"ndjson"));
        });
    }
    private static String csv(String raw) {
        String value=raw;
        if(raw.matches("(?s)^[\\s\\uFEFF]*[=+@-].*") || (!raw.isEmpty() && Character.isISOControl(raw.charAt(0))))value="'"+raw;
        return "\""+value.replace("\"","\"\"")+"\"";
    }
}
