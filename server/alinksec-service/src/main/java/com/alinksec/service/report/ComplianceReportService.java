package com.alinksec.service.report;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.config.DatabaseDialect;
import com.alinksec.service.scan.VulnerabilityEvidence;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;

/** One consistent database view feeds every report format and its retained snapshot. */
@Service
public class ComplianceReportService {
    public static final int DETAIL_LIMIT=500, MAX_SNAPSHOTS=200, MAX_BYTES=2*1024*1024;
    private final JdbcTemplate jdbc;
    private final DatabaseDialect database;
    private final TransactionTemplate tx;
    public ComplianceReportService(JdbcTemplate jdbc,DatabaseDialect database,PlatformTransactionManager manager) {
        this.jdbc=jdbc;this.database=database;tx=new TransactionTemplate(manager);
        if(!database.isSqlite())tx.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
    }
    public Map<String,Object> preview(ReportQuery query) {
        Instant now=Instant.now();ReportQuery q=query.checked(now);return tx.execute(s->capture(q,now));
    }
    public byte[] csv(String from,String to){return ReportExport.render(preview(new ReportQuery(from,to,null,null)),"csv");}
    private List<Object> scopeArgs(ReportQuery q) {
        var a=new ArrayList<Object>();if(q.groupId()!=null)a.add(q.groupId());if(q.osType()!=null)a.add(q.osType());return a;
    }
    private String scope(ReportQuery q) {
        return "a.deleted=false AND a.status<>4"+(q.groupId()==null?"":" AND a.group_id=?")+(q.osType()==null?"":" AND a.os_type=?");
    }
    private Object boundary(Instant at) {
        return database.isSqlite()?java.time.format.DateTimeFormatter.ofPattern("uuuu-MM-dd HH:mm:ss").withZone(ZoneOffset.UTC).format(at):database.timestamp(at);
    }
    private List<Object> periodArgs(ReportQuery q) {
        var a=scopeArgs(q);a.add(boundary(q.start()));a.add(boundary(q.endExclusive()));return a;
    }
    private Map<String,Object> capture(ReportQuery q,Instant now) {
        if(q.groupId()!=null && jdbc.queryForObject("SELECT COUNT(*) FROM t_host_group WHERE id=?",Integer.class,q.groupId())!=1)
            throw new IllegalArgumentException("所选分组不存在");
        var report=new LinkedHashMap<String,Object>();report.put("contract",1);report.put("title","ALinkSec 安全运营报表");
        report.put("generatedAt",now.toString());report.put("timezone",ReportQuery.ZONE.toString());report.put("query",q);
        report.put("period",Map.of("fromInclusive",q.start().toString(),"toExclusive",q.endExclusive().toString()));
        report.put("scope",Map.of("group",q.groupId()==null?"全部分组（含未分组）":jdbc.queryForObject("SELECT name FROM t_host_group WHERE id=?",String.class,q.groupId()),
                "os",q.osType()==null?"全部系统":q.osType()==1?"Linux":"Windows","deletedHostsExcluded",true));
        report.put("notes",List.of("日期按 Asia/Shanghai 自然日计算，包含结束日。分组只包含直接归属主机。已删除主机及其事件不在本报表范围。",
                "主机和漏洞覆盖是生成时的当前快照；基线采用区间内最后分配任务，未回报不会回退到较早的通过结果。",
                "基线通过率仅指自动检查项通过数 / 预期项数；异常、旧证据、待回报分别列出，不代表等保认证结论。",
                "漏洞按发现记录创建时间统计，同一 CVE 可有多条记录；已记录的匹配标记不证明当前适用或已修复。零发现、无规则和未采集均不能证明安全。",
                "告警按首次发生时间统计，处置状态以生成时为准；合并次数单列，未按次数重复计数。",
                "明细最多展示 500 台主机；汇总和趋势覆盖全部所选主机。历史快照保留 30 天，全平台最多 200 份。"));
        var args=scopeArgs(q);
        report.put("assets",jdbc.queryForMap("SELECT COUNT(*) AS total,COALESCE(SUM(CASE WHEN status=1 THEN 1 ELSE 0 END),0) AS online,"
                +"COALESCE(SUM(CASE WHEN status=2 THEN 1 ELSE 0 END),0) AS offline,"
                +"COALESCE(SUM(CASE WHEN status NOT IN (1,2) THEN 1 ELSE 0 END),0) AS other FROM t_agent a WHERE "+scope(q),args.toArray()));
        String base="""
                WITH scoped AS (SELECT a.* FROM t_agent a WHERE %s),choices AS (
                  SELECT e.agent_id,e.task_id,COUNT(*) AS expected,0 AS old_snapshot,t.created_at
                  FROM t_baseline_task_expected e JOIN scoped a ON a.agent_id=e.agent_id
                  JOIN t_baseline_task t ON t.id=e.task_id WHERE t.created_at>=? AND t.created_at<?
                  GROUP BY e.agent_id,e.task_id,t.created_at
                  UNION ALL
                  SELECT s.agent_id,s.task_id,s.total,1,t.created_at FROM t_baseline_summary s
                  JOIN scoped a ON a.agent_id=s.agent_id JOIN t_baseline_task t ON t.id=s.task_id
                  WHERE t.created_at>=? AND t.created_at<? AND NOT EXISTS
                    (SELECT 1 FROM t_baseline_task_expected e WHERE e.task_id=s.task_id AND e.agent_id=s.agent_id)
                ),ranked AS (SELECT choices.*,ROW_NUMBER() OVER(PARTITION BY agent_id ORDER BY created_at DESC,task_id DESC) AS rn FROM choices),
                outcomes AS (SELECT r.agent_id,r.task_id,
                  SUM(CASE WHEN r.execution_status='pass' THEN 1 ELSE 0 END) AS passed,
                  SUM(CASE WHEN r.execution_status='fail' THEN 1 ELSE 0 END) AS failed,
                  SUM(CASE WHEN r.execution_status='error' THEN 1 ELSE 0 END) AS errors,
                  SUM(CASE WHEN r.execution_status='legacy' THEN 1 ELSE 0 END) AS legacy,COUNT(*) AS received
                  FROM t_baseline_result r JOIN ranked x ON x.agent_id=r.agent_id AND x.task_id=r.task_id AND x.rn=1
                  WHERE EXISTS (SELECT 1 FROM t_baseline_task_expected e WHERE e.task_id=r.task_id AND e.agent_id=r.agent_id AND e.item_id=r.item_id)
                  GROUP BY r.agent_id,r.task_id),hostview AS (
                  SELECT a.agent_id,a.hostname,a.os_type,a.status,a.group_id,x.task_id,t.name AS task_name,
                  COALESCE(x.expected,0) AS expected,
                  CASE WHEN x.old_snapshot=1 THEN 0 ELSE COALESCE(o.passed,0) END AS passed,
                  CASE WHEN x.old_snapshot=1 THEN 0 ELSE COALESCE(o.failed,0) END AS failed,
                  CASE WHEN x.old_snapshot=1 THEN 0 ELSE COALESCE(o.errors,0) END AS errors,
                  CASE WHEN x.old_snapshot=1 THEN x.expected ELSE COALESCE(o.legacy,0) END AS legacy,
                  CASE WHEN x.old_snapshot=1 THEN 0 WHEN COALESCE(x.expected,0)>COALESCE(o.received,0) THEN x.expected-COALESCE(o.received,0) ELSE 0 END AS pending
                  FROM scoped a LEFT JOIN ranked x ON x.agent_id=a.agent_id AND x.rn=1
                  LEFT JOIN outcomes o ON o.agent_id=x.agent_id AND o.task_id=x.task_id
                  LEFT JOIN t_baseline_task t ON t.id=x.task_id)
                """.formatted(scope(q));
        var baselineArgs=periodArgs(q);baselineArgs.add(boundary(q.start()));baselineArgs.add(boundary(q.endExclusive()));
        report.put("baseline",jdbc.queryForMap(base+"SELECT COUNT(task_id) AS assigned_hosts,COUNT(*)-COUNT(task_id) AS unassessed_hosts,"
                +"COALESCE(SUM(expected),0) AS expected,COALESCE(SUM(passed),0) AS passed,COALESCE(SUM(failed),0) AS failed,"
                +"COALESCE(SUM(errors),0) AS errors,COALESCE(SUM(legacy),0) AS legacy,COALESCE(SUM(pending),0) AS pending FROM hostview",baselineArgs.toArray()));
        report.put("hosts",jdbc.queryForList(base+"SELECT * FROM hostview ORDER BY hostname,agent_id LIMIT "+DETAIL_LIMIT,baselineArgs.toArray()));
        long total=((Number)((Map<?,?>)report.get("assets")).get("total")).longValue();
        report.put("detailsTruncated",total>DETAIL_LIMIT);report.put("detailTotal",total);report.put("detailLimit",DETAIL_LIMIT);
        String coverage="""
                CASE WHEN a.software_collection_status<>'complete' THEN a.software_collection_status
                  WHEN v.agent_id IS NULL THEN 'not_scanned'
                  WHEN v.inventory_revision<>a.software_revision THEN 'stale_inventory'
                  WHEN v.rule_revision<>(SELECT revision FROM t_vuln_rule_state WHERE id=1) THEN 'stale_rules'
                  WHEN (SELECT match_pending FROM t_security_selection_delivery WHERE id=1)=1 THEN 'selection_pending'
                  ELSE v.status END
                """;
        report.put("coverage",jdbc.queryForList("SELECT "+coverage+" AS status,COUNT(*) AS hosts FROM t_agent a LEFT JOIN t_vuln_coverage v ON v.agent_id=a.agent_id WHERE "+scope(q)+" GROUP BY "+coverage+" ORDER BY status",args.toArray()));
        report.put("sourceHolds",jdbc.queryForList("SELECT rule_status AS status,COUNT(*) AS items FROM t_cve_db WHERE rule_status IN ('conflict','review_required','quarantined','suppressed','withdrawn','retired') GROUP BY rule_status ORDER BY rule_status"));
        report.put("sourceHoldsScope","全平台 CVE 声明目录，独立于主机筛选，不代表受影响主机数");
        report.put("vulnerabilities",jdbc.queryForList("""
                SELECT f.severity,f.status,COUNT(*) AS records,SUM(CASE WHEN f.current_match=true THEN 1 ELSE 0 END) AS recorded_match
                FROM t_agent a JOIN t_vuln_finding f ON f.agent_id=a.agent_id WHERE
                """+scope(q)+" AND f.created_at>=? AND f.created_at<? GROUP BY f.severity,f.status ORDER BY f.severity DESC,f.status",periodArgs(q).toArray()));
        report.put("alerts",jdbc.queryForList("""
                SELECT f.severity,COUNT(*) AS records,COALESCE(SUM(f.count),0) AS occurrences,
                  SUM(CASE WHEN f.status=2 THEN 1 ELSE 0 END) AS handled,SUM(CASE WHEN f.status=3 THEN 1 ELSE 0 END) AS ignored,
                  SUM(CASE WHEN f.status NOT IN (2,3) THEN 1 ELSE 0 END) AS open
                FROM t_agent a JOIN t_alert f ON f.agent_id=a.agent_id WHERE
                """+scope(q)+" AND f.first_time>=? AND f.first_time<? GROUP BY f.severity ORDER BY f.severity DESC",periodArgs(q).toArray()));
        String day=database.isSqlite()?"strftime('%Y-%m-%d',f.{column},'+8 hours')":"to_char(f.{column} AT TIME ZONE 'Asia/Shanghai','YYYY-MM-DD')";
        var trend=new LinkedHashMap<String,Map<String,Object>>();
        for(LocalDate d=LocalDate.parse(q.from());!d.isAfter(LocalDate.parse(q.to()));d=d.plusDays(1))
            trend.put(d.toString(),new LinkedHashMap<>(Map.of("day",d.toString(),"alerts",0L,"vulnerabilities",0L)));
        for(var entry:Map.of("alerts",List.of("t_alert","first_time"),"vulnerabilities",List.of("t_vuln_finding","created_at")).entrySet()) {
            String column=entry.getValue().get(1),bucket=day.replace("{column}",column);
            for(var row:jdbc.queryForList("SELECT "+bucket+" AS day,COUNT(*) AS records FROM t_agent a JOIN "+entry.getValue().get(0)+" f ON f.agent_id=a.agent_id WHERE "+scope(q)+" AND f."+column+">=? AND f."+column+"<? GROUP BY "+bucket,periodArgs(q).toArray())) {
                var point=trend.get(row.get("day").toString());if(point==null)throw new IllegalStateException("报表日期桶超出选择范围");point.put(entry.getKey(),row.get("records"));
            }
        }
        report.put("trend",new ArrayList<>(trend.values()));
        var commitment=JsonUtils.read(JsonUtils.write(report)).deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)commitment).remove(List.of("generatedAt","title"));
        report.put("dataDigest",VulnerabilityEvidence.sha256(VulnerabilityEvidence.canonicalJson(commitment)));
        String document=JsonUtils.write(report);if(document.getBytes(StandardCharsets.UTF_8).length>MAX_BYTES)throw new IllegalArgumentException("报表超过 2 MiB 上限，请缩小筛选范围");
        return JsonUtils.read(document,LinkedHashMap.class);
    }
    private void gate(){if(jdbc.update("UPDATE t_report_gate SET revision=revision+1 WHERE id=1")!=1)throw new IllegalStateException("报表锁不存在");}
    private void writer(Long actor,boolean admin) {
        if(actor==null || actor<=0 || jdbc.update("UPDATE t_user SET status=status WHERE id=? AND status=1",actor)!=1
                || jdbc.queryForObject("SELECT COUNT(*) FROM t_user u JOIN t_role r ON r.id=u.role_id WHERE u.id=? AND r.name IN "+(admin?"('admin')":"('admin','operator')"),Integer.class,actor)!=1)
            throw new IllegalArgumentException(admin?"需要当前有效管理员":"需要当前有效管理员或操作员");
    }
    private static String title(String value) {
        if(value==null || value.isBlank() || value.length()>128 || value.codePoints().anyMatch(Character::isISOControl))throw new IllegalArgumentException("报表名称须为 1 至 128 字且无控制字符");return value.trim();
    }
    private void prune(Instant now){jdbc.update("DELETE FROM t_report_snapshot WHERE expires_at<=?",now.toEpochMilli());}
    public Map<String,Object> save(ReportQuery query,String title,Long actor) {
        Instant now=Instant.now();ReportQuery q=query.checked(now);String name=title(title);
        return tx.execute(s->{writer(actor,false);gate();prune(now);return store(capture(q,now),name,actor,null,null,now);});
    }
    private Map<String,Object> store(Map<String,Object> report,String title,Long actor,String schedule,Long due,Instant now) {
        if(jdbc.queryForObject("SELECT COUNT(*) FROM t_report_snapshot",Integer.class)>=MAX_SNAPSHOTS)throw new IllegalArgumentException("报表历史已达 200 份，请由管理员删除旧快照或等待到期");
        String id=UUID.randomUUID().toString();report.put("title",title);report.put("snapshotId",id);report.put("createdBy",actor);report.put("expiresAt",now.plus(Duration.ofDays(30)).toString());String document=JsonUtils.write(report);
        if(document.getBytes(StandardCharsets.UTF_8).length>MAX_BYTES)throw new IllegalArgumentException("报表快照超过 2 MiB 上限");
        jdbc.update("INSERT INTO t_report_snapshot(id,title,created_by,generated_at,expires_at,schedule_id,scheduled_at,document,sha256) VALUES (?,?,?,?,?,?,?,?,?)",
                id,title,actor,now.toEpochMilli(),now.plus(Duration.ofDays(30)).toEpochMilli(),schedule,due,document,VulnerabilityEvidence.sha256(document));
        return snapshot(id);
    }
    public Map<String,Object> history(int page,int size) {
        page(page,size);long now=Instant.now().toEpochMilli();return tx.execute(s->Map.of("total",jdbc.queryForObject("SELECT COUNT(*) FROM t_report_snapshot WHERE expires_at>?",Long.class,now),
                "list",jdbc.queryForList("SELECT id,title,created_by,generated_at,expires_at,schedule_id,scheduled_at,sha256 FROM t_report_snapshot WHERE expires_at>? ORDER BY generated_at DESC,id LIMIT ? OFFSET ?",now,size,(page-1)*size),"retentionDays",30,"capacity",MAX_SNAPSHOTS));
    }
    private static void page(int page,int size){if(page<1 || page>10000 || size<1 || size>50)throw new IllegalArgumentException("分页范围无效");}
    private static void id(String id){try{if(!UUID.fromString(id).toString().equals(id))throw new IllegalArgumentException();}catch(RuntimeException e){throw new IllegalArgumentException("报表标识无效");}}
    public Map<String,Object> snapshot(String id) {
        id(id);var rows=jdbc.queryForList("SELECT * FROM t_report_snapshot WHERE id=? AND expires_at>?",id,Instant.now().toEpochMilli());
        if(rows.size()!=1)throw new IllegalArgumentException("报表不存在或已过期");var row=rows.get(0);String document=(String)row.remove("document");
        if(document.getBytes(StandardCharsets.UTF_8).length>MAX_BYTES || !VulnerabilityEvidence.sha256(document).equals(row.get("sha256")))throw new IllegalStateException("报表快照摘要不一致，禁止导出");
        row.put("report",JsonUtils.read(document,LinkedHashMap.class));return row;
    }
    public void delete(String id,Long actor){id(id);tx.executeWithoutResult(s->{writer(actor,true);gate();if(jdbc.update("DELETE FROM t_report_snapshot WHERE id=?",id)!=1)throw new IllegalArgumentException("报表不存在");});}
    public record ScheduleRequest(String title,String cadence,Integer days,Long groupId,Integer osType,Boolean enabled,Long revision){}
    public List<Map<String,Object>> schedules(){return jdbc.queryForList("SELECT * FROM t_report_schedule ORDER BY title,id LIMIT 50");}
    public Map<String,Object> schedule(String id,ScheduleRequest body,Long actor) {
        if(id!=null)id(id);if(body==null || body.days()==null || body.days()<1 || body.days()>366 || body.enabled()==null || body.revision()==null || body.revision()<0
                || !Set.of("daily","weekly","monthly").contains(Objects.toString(body.cadence(),"")))throw new IllegalArgumentException("定时报表计划无效");
        String name=title(body.title());Instant now=Instant.now();new ReportQuery(null,null,body.groupId(),body.osType()).checked(now);
        return tx.execute(s->{writer(actor,true);gate();
            if(body.groupId()!=null && jdbc.queryForObject("SELECT COUNT(*) FROM t_host_group WHERE id=?",Integer.class,body.groupId())!=1)throw new IllegalArgumentException("分组不存在");
            String key=id==null?UUID.randomUUID().toString():id;
            if(id==null) {
                if(body.revision()!=0 || jdbc.queryForObject("SELECT COUNT(*) FROM t_report_schedule",Integer.class)>=50)throw new IllegalArgumentException("计划已达 50 条上限或修订无效");
                jdbc.update("INSERT INTO t_report_schedule(id,title,cadence,days,group_id,os_type,enabled,revision,owner_id,next_run,retry_at,failures,last_error) VALUES (?,?,?,?,?,?,?,1,?,?,?,0,'')",
                        key,name,body.cadence(),body.days(),body.groupId(),body.osType(),body.enabled()?1:0,actor,next(body.cadence(),now).toEpochMilli(),0L);
            }else if(jdbc.update("UPDATE t_report_schedule SET title=?,cadence=?,days=?,group_id=?,os_type=?,enabled=?,revision=revision+1,owner_id=?,next_run=?,retry_at=0,failures=0,last_error='' WHERE id=? AND revision=?",
                    name,body.cadence(),body.days(),body.groupId(),body.osType(),body.enabled()?1:0,actor,next(body.cadence(),now).toEpochMilli(),id,body.revision())!=1)throw new IllegalArgumentException("计划已变化，请刷新后重试");
            return jdbc.queryForMap("SELECT * FROM t_report_schedule WHERE id=?",key);
        });
    }
    public void deleteSchedule(String id,long revision,Long actor){id(id);tx.executeWithoutResult(s->{writer(actor,true);gate();if(jdbc.update("DELETE FROM t_report_schedule WHERE id=? AND revision=?",id,revision)!=1)throw new IllegalArgumentException("计划已变化，请刷新后重试");});}
    public static Instant next(String cadence,Instant after) {
        var day=after.atZone(ReportQuery.ZONE).toLocalDate();
        for(int i=0;i<33;i++,day=day.plusDays(1)) {
            Instant candidate=day.atTime(9,0).atZone(ReportQuery.ZONE).toInstant();
            if(candidate.isAfter(after) && (cadence.equals("daily") || cadence.equals("weekly") && day.getDayOfWeek()==DayOfWeek.MONDAY || cadence.equals("monthly") && day.getDayOfMonth()==1))return candidate;
        }
        throw new IllegalArgumentException("定时频率无效");
    }
    /** Slot advancement and its report commit in the same database transaction. */
    public void runDue(Instant now) {
        if(jdbc.queryForObject("SELECT COUNT(*) FROM t_report_snapshot WHERE expires_at<=?",Integer.class,now.toEpochMilli())>0)tx.executeWithoutResult(s->{gate();prune(now);});
        for(var item:jdbc.queryForList("SELECT id,owner_id FROM t_report_schedule WHERE enabled=1 AND next_run<=? AND retry_at<=? ORDER BY next_run,id LIMIT 4",now.toEpochMilli(),now.toEpochMilli())) {
            String id=(String)item.get("id");Long owner=((Number)item.get("owner_id")).longValue();
            try {
                tx.executeWithoutResult(s->{writer(owner,true);gate();prune(now);var rows=jdbc.queryForList("SELECT * FROM t_report_schedule WHERE id=? AND enabled=1 AND next_run<=? AND retry_at<=?",id,now.toEpochMilli(),now.toEpochMilli());if(rows.isEmpty())return;
                    var row=rows.get(0);if(((Number)row.get("owner_id")).longValue()!=owner)return;
                    long due=((Number)row.get("next_run")).longValue();LocalDate end=Instant.ofEpochMilli(due).atZone(ReportQuery.ZONE).toLocalDate().minusDays(1);
                    var q=new ReportQuery(end.minusDays(((Number)row.get("days")).intValue()-1).toString(),end.toString(),row.get("group_id")==null?null:((Number)row.get("group_id")).longValue(),row.get("os_type")==null?null:((Number)row.get("os_type")).intValue()).checked(now);
                    var saved=store(capture(q,now),(String)row.get("title"),owner,id,due,now);
                    jdbc.update("UPDATE t_report_schedule SET next_run=?,retry_at=0,failures=0,last_error='',last_snapshot=?,last_run=? WHERE id=?",next((String)row.get("cadence"),now).toEpochMilli(),saved.get("id"),now.toEpochMilli(),id);
                });
            }catch(RuntimeException failure) {
                // No partial report survives failure; exception text could contain SQL or credentials.
                tx.executeWithoutResult(s->{gate();boolean valid=jdbc.queryForObject("SELECT COUNT(*) FROM t_user u JOIN t_role r ON r.id=u.role_id WHERE u.id=? AND u.status=1 AND r.name='admin'",Integer.class,owner)==1;
                    jdbc.update("UPDATE t_report_schedule SET failures=failures+1,retry_at=?,last_error=?,enabled=CASE WHEN failures>=2 OR ?=0 THEN 0 ELSE enabled END WHERE id=? AND owner_id=? AND enabled=1 AND next_run<=? AND retry_at<=?",now.plusSeconds(300).toEpochMilli(),valid?"生成失败；五分钟后重试，连续三次失败停用":"计划所有者已停用或不再是管理员，计划已停止",valid?1:0,id,owner,now.toEpochMilli(),now.toEpochMilli());});
            }
        }
    }
}
