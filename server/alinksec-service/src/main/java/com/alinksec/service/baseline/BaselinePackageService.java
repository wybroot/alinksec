package com.alinksec.service.baseline;

import com.alinksec.common.util.JsonUtils;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.util.*;

/** Candidate -> administrator review -> explicit test -> publication. Documents are immutable. */
@Service
public class BaselinePackageService {
    private final JdbcTemplate jdbc;
    private final BaselineTaskService tasks;
    public BaselinePackageService(JdbcTemplate jdbc, BaselineTaskService tasks) {
        this.jdbc = jdbc; this.tasks = tasks;
    }

    @Transactional(rollbackFor = Exception.class)
    public Map<String, Object> importPackage(InputStream input, Long user) throws IOException {
        var validated = BaselinePackageFormat.read(input);
        JsonNode doc = validated.document();
        String code = doc.path("code").asText(), version = doc.path("version").asText();
        jdbc.update("INSERT INTO t_baseline_package_gate(code) VALUES (?) ON CONFLICT(code) DO NOTHING", code);
        lock(code);
        var existing = jdbc.queryForList("SELECT id,content_sha256 FROM t_baseline_package WHERE code=? AND version=?", code, version);
        if (!existing.isEmpty()) {
            require(validated.sha256().equals(existing.get(0).get("content_sha256")), "同一模板版本已有不同内容，请使用新版本号");
            return detail(String.valueOf(existing.get(0).get("id")));
        }
        String id = UUID.randomUUID().toString();
        jdbc.update("""
                INSERT INTO t_baseline_package(id,code,version,content_sha256,document,base_package_id,imported_by,created_at,name,os_type,product,supported_count,unsupported_count)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, id, code, version, validated.sha256(), JsonUtils.write(doc), active(code), user, now(), doc.path("name").asText(), doc.path("osType").intValue(), doc.path("product").asText(), doc.path("items").size(), doc.path("unsupported").size());
        return detail(id);
    }

    public List<Map<String, Object>> list() {
        return jdbc.queryForList("""
                SELECT id,code,name,os_type,product,supported_count,unsupported_count,version,content_sha256,status,template_id,test_task_id,created_at,reviewed_at,published_at,
                       imported_by,reviewed_by,review_note,publication_note
                FROM t_baseline_package ORDER BY created_at DESC,id DESC LIMIT 200
                """);
    }

    public Map<String, Object> detail(String id) {
        Map<String, Object> result = new LinkedHashMap<>(row(id));
        JsonNode doc = JsonUtils.read(String.valueOf(result.get("document")));
        result.put("document", doc);
        JsonNode previous = null;
        if (result.get("base_package_id") != null) previous = JsonUtils.read(String.valueOf(row(String.valueOf(result.get("base_package_id"))).get("document")));
        result.put("diff", diff(previous, doc));
        List<Map<String, Object>> metadataDiff = new ArrayList<>();
        for (String field : List.of("name", "standard", "product", "osType", "osVersionPattern", "version", "source")) {
            JsonNode oldValue = previous == null ? null : previous.path(field);
            if (!Objects.equals(oldValue, doc.path(field))) {
                Map<String, Object> change = new LinkedHashMap<>(); change.put("field", field); change.put("before", oldValue); change.put("after", doc.path(field)); metadataDiff.add(change);
            }
        }
        result.put("metadataDiff", metadataDiff);
        result.put("testTargets", jdbc.queryForList("SELECT agent_id,hostname,os_type,os_version FROM t_agent WHERE deleted=false ORDER BY agent_id LIMIT 500")
                .stream().filter(agent -> BaselinePackageFormat.applies(doc.path("osType").intValue(), doc.path("osVersionPattern").asText(), agent)).toList());
        if (result.get("test_task_id") != null) {
            long task = ((Number) result.get("test_task_id")).longValue();
            result.put("testTask", jdbc.queryForMap("SELECT id,task_no,status,progress FROM t_baseline_task WHERE id=?", task));
            var summaries = jdbc.queryForList("SELECT agent_id,total,passed_count,failed_count,score,error_count,legacy_count FROM t_baseline_summary WHERE task_id=?", task);
            for (var summary : summaries) summary.put("items", jdbc.queryForList("""
                    SELECT i.code,i.name,i.rule_id,r.passed,r.actual,r.message,r.execution_status,r.duration_ms FROM t_baseline_result r
                    JOIN v_baseline_result_definition i ON i.result_id=r.id
                    WHERE r.task_id=? AND r.agent_id=? ORDER BY i.code
                    """, task, summary.get("agent_id")));
            result.put("testResults", summaries);
            result.put("testReady", ((Number) ((Map<?, ?>) result.get("testTask")).get("status")).intValue() == 2
                    && !summaries.isEmpty() && summaries.stream().allMatch(summary ->
                    ((Number) summary.get("error_count")).intValue() == 0 && ((Number) summary.get("legacy_count")).intValue() == 0));
        }
        return result;
    }

    @Transactional
    public Map<String, Object> review(String id, boolean approve, String note, Long user) {
        Map<String, Object> pkg = locked(id);
        require("candidate".equals(pkg.get("status")), "只有待审核版本可以审核");
        note = note(note); if (approve) ensureBase(pkg);
        Long template = null;
        if (approve) {
            JsonNode doc = JsonUtils.read(String.valueOf(pkg.get("document")));
            template = jdbc.queryForObject("""
                    INSERT INTO t_baseline_template(code,name,standard,os_type,version,item_count,enabled,package_id,os_version_pattern)
                    VALUES (?,?,?,?,?,?,false,?,?) RETURNING id
                    """, Long.class, pkg.get("code") + "-" + id.substring(0, 16), doc.path("name").asText(),
                    doc.path("standard").asText(), doc.path("osType").intValue(), doc.path("version").asText(),
                    doc.path("items").size(), id, doc.path("osVersionPattern").asText());
            for (JsonNode item : doc.path("items")) jdbc.update("""
                    INSERT INTO t_baseline_item(template_id,code,name,category,severity,"check",remediation,rule_id)
                    VALUES (?,?,?,?,?,?,?,?)
                    """, template, item.path("code").asText(), item.path("name").asText(), item.path("category").asText(),
                    item.path("severity").intValue(), JsonUtils.write(item.path("check")), item.path("remediation").asText(""), item.path("ruleId").asText());
        }
        jdbc.update("UPDATE t_baseline_package SET status=?,template_id=?,reviewed_by=?,review_note=?,reviewed_at=? WHERE id=?",
                approve ? "approved" : "rejected", template, user, note, now(), id);
        return detail(id);
    }

    @Transactional
    public Map<String, Object> test(String id, List<String> agents, Long user) {
        Map<String, Object> pkg = locked(id);
        require("approved".equals(pkg.get("status")), "只有已审核候选版本可以测试");
        require(agents != null && !agents.isEmpty() && agents.size() <= 10, "测试需选择 1 至 10 台主机");
        if (pkg.get("test_task_id") instanceof Number task) {
            int status = jdbc.queryForObject("SELECT status FROM t_baseline_task WHERE id=?", Integer.class, task.longValue());
            require(status != 0 && status != 1, "该候选版本已有执行中的测试");
        }
        long task = tasks.createReviewTask("候选模板测试 " + pkg.get("code") + " " + pkg.get("version"),
                agents, ((Number) pkg.get("template_id")).longValue(), user);
        jdbc.update("UPDATE t_baseline_package SET test_task_id=? WHERE id=?", task, id);
        return detail(id);
    }

    @Transactional
    public Map<String, Object> publish(String id, String note, Long user) {
        Map<String, Object> pkg = locked(id);
        require("approved".equals(pkg.get("status")), "只有已审核候选版本可以发布");
        note = note(note); ensureBase(pkg);
        require(pkg.get("test_task_id") instanceof Number, "发布前需在适用测试主机上完成核查");
        long test = ((Number) pkg.get("test_task_id")).longValue();
        require(jdbc.queryForObject("SELECT status FROM t_baseline_task WHERE id=?", Integer.class, test) == 2,
                "测试核查尚未完整结束，不能发布");
        require(jdbc.queryForObject("SELECT count(*) FROM t_baseline_summary WHERE task_id=?", Integer.class, test) > 0,
                "缺少测试主机核查结果");
        require(jdbc.queryForObject("SELECT count(*) FROM t_baseline_summary WHERE task_id=? AND (error_count>0 OR legacy_count>0)", Integer.class, test) == 0,
                "测试存在执行异常或旧 Agent 无法区分的结果，请更新 Agent 并重新测试后发布");
        // Publishing selects a version; it does not run checks or repairs on other hosts.
        String previous = active(String.valueOf(pkg.get("code")));
        if (previous != null) {
            jdbc.update("UPDATE t_baseline_template SET enabled=false WHERE package_id=?", previous);
            jdbc.update("UPDATE t_baseline_package SET status='withdrawn' WHERE id=?", previous);
        }
        jdbc.update("UPDATE t_baseline_template SET enabled=true WHERE id=?", pkg.get("template_id"));
        jdbc.update("UPDATE t_baseline_package SET status='published',publication_note=?,published_at=? WHERE id=?", note, now(), id);
        return detail(id);
    }

    @Transactional
    public Map<String, Object> withdraw(String id, String note) {
        Map<String, Object> pkg = locked(id);
        require("published".equals(pkg.get("status")) || "approved".equals(pkg.get("status")), "只有发布或已审核版本可以撤回");
        jdbc.update("UPDATE t_baseline_template SET enabled=false WHERE id=?", pkg.get("template_id"));
        jdbc.update("UPDATE t_baseline_package SET status='withdrawn',publication_note=? WHERE id=?", note(note), id);
        return detail(id);
    }

    private Map<String, Object> row(String id) {
        var rows = jdbc.queryForList("SELECT * FROM t_baseline_package WHERE id=?", id);
        require(!rows.isEmpty(), "模板包不存在"); return rows.get(0);
    }
    private Map<String, Object> locked(String id) { Map<String, Object> pkg = row(id); lock(String.valueOf(pkg.get("code"))); return row(id); }
    private void lock(String code) { jdbc.update("UPDATE t_baseline_package_gate SET revision=revision+1 WHERE code=?", code); }
    private String active(String code) {
        var rows = jdbc.queryForList("SELECT id FROM t_baseline_package WHERE code=? AND status='published'", code);
        return rows.isEmpty() ? null : String.valueOf(rows.get(0).get("id"));
    }
    private void ensureBase(Map<String, Object> pkg) {
        require(Objects.equals(pkg.get("base_package_id"), active(String.valueOf(pkg.get("code")))), "当前发布版本已变化，请基于最新版本重新导入并审查差异");
    }
    private static String now() { return Instant.now().toString(); }
    private static String note(String value) { require(value != null && !value.isBlank() && value.length() <= 2000, "请填写不超过 2000 字的审核/发布说明"); return value.trim(); }
    private static void require(boolean value, String message) { if (!value) throw new IllegalArgumentException(message); }
    private static Map<String, JsonNode> rules(JsonNode doc) {
        Map<String, JsonNode> result = new TreeMap<>();
        if (doc != null) for (String field : List.of("items", "unsupported")) doc.path(field).forEach(item -> result.put(item.path("ruleId").asText(), item));
        return result;
    }
    private static List<Map<String, Object>> diff(JsonNode before, JsonNode after) {
        var old = rules(before); var next = rules(after); Set<String> ids = new TreeSet<>(old.keySet()); ids.addAll(next.keySet());
        List<Map<String, Object>> changes = new ArrayList<>();
        for (String id : ids) if (!Objects.equals(old.get(id), next.get(id))) {
            Map<String, Object> change = new LinkedHashMap<>();
            change.put("ruleId", id); change.put("change", !old.containsKey(id) ? "added" : !next.containsKey(id) ? "removed" : "changed");
            change.put("before", old.get(id)); change.put("after", next.get(id)); changes.add(change);
        }
        return changes;
    }
}
