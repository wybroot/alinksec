package com.alinksec.service.baseline;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.config.DatabaseDialect;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Clause conclusions require both the immutable automatic evidence and a human review. */
@Service
public class BaselineComplianceService {
    private final JdbcTemplate jdbc;
    public BaselineComplianceService(JdbcTemplate jdbc) { this.jdbc = jdbc; }
    public record Decision(long templateId, String controlId, int revision, String decision, String note, String evidenceRef) {}

    @Transactional(readOnly = true)
    public List<Map<String, Object>> assessment(long taskId, String agentId) {
        var templates = jdbc.queryForList("""
                SELECT st.*,CAST(p.document AS TEXT) AS document FROM t_baseline_task_template st
                JOIN t_baseline_package p ON p.id=st.package_id
                WHERE st.task_id=? AND EXISTS (
                  SELECT 1 FROM t_baseline_task_item i JOIN t_baseline_task_expected e
                    ON e.task_id=i.task_id AND e.item_id=i.item_id
                  WHERE i.task_id=st.task_id AND i.template_id=st.template_id AND e.agent_id=?)
                ORDER BY st.template_id
                """, taskId, agentId);
        List<Map<String, Object>> profiles = new ArrayList<>();
        for (var template : templates) {
            var document = JsonUtils.read((String) template.get("document"));
            if (!document.has("compliance")) continue;
            try {
                var validated = BaselinePackageFormat.read(new ByteArrayInputStream(((String) template.get("document")).getBytes(StandardCharsets.UTF_8)));
                if (!validated.sha256().equals(template.get("content_sha256"))) throw new IllegalArgumentException("合规包快照摘要不一致");
            } catch (java.io.IOException e) { throw new IllegalArgumentException("合规包快照无法读取"); }
            long templateId = ((Number) template.get("template_id")).longValue();
            var evidence = jdbc.queryForList("""
                    SELECT i.code,i.name,i."check",r.passed,r.execution_status,r.actual,r.message
                    FROM t_baseline_task_item i JOIN t_baseline_task_expected e ON e.task_id=i.task_id AND e.item_id=i.item_id
                    LEFT JOIN t_baseline_result r ON r.task_id=e.task_id AND r.agent_id=e.agent_id AND r.item_id=e.item_id
                    WHERE i.task_id=? AND i.template_id=? AND e.agent_id=? ORDER BY i.code
                    """, taskId, templateId, agentId);
            Map<String, Map<String, Object>> byCode = new HashMap<>();
            evidence.forEach(e -> byCode.put((String) e.get("code"), e));
            if (byCode.size() != document.path("items").size()) throw new IllegalArgumentException("合规检查快照不完整");
            for (var item : document.path("items")) {
                var actual = byCode.get(item.path("code").asText());
                if (actual == null || !item.path("check").equals(JsonUtils.read(String.valueOf(actual.get("check")))))
                    throw new IllegalArgumentException("合规检查定义与包快照不一致");
            }
            var coverage = new LinkedHashMap<>(BaselineComplianceCatalog.coverage(document));
            List<Map<String, Object>> controls = new ArrayList<>();
            Map<String, Integer> counts = new LinkedHashMap<>();
            for (String state : List.of("pass", "fail", "error", "pending", "not_applicable")) counts.put(state, 0);
            var catalog = BaselineComplianceCatalog.catalog(document.path("compliance").path("catalogId").asText());
            var histories = jdbc.queryForList("SELECT * FROM t_baseline_compliance_review WHERE task_id=? AND agent_id=? AND template_id=? ORDER BY revision DESC",
                    taskId, agentId, templateId);
            for (var control : catalog.path("controls")) {
                String id = control.path("id").asText();
                JsonNode codes = document.path("compliance").path("controlChecks").path(id);
                List<Map<String, Object>> checks = new ArrayList<>();
                String automatic = "pass";
                for (var code : codes) {
                    var check = new LinkedHashMap<>(byCode.get(code.asText())); check.remove("check"); checks.add(check);
                    Object status = check.get("execution_status");
                    if (status == null) { if (automatic.equals("pass")) automatic = "pending"; }
                    else if (!Set.of("pass", "fail").contains(status)) automatic = "error";
                    else if (status.equals("fail") || !DatabaseDialect.readBoolean(check.get("passed"))) {
                        if (!automatic.equals("error")) automatic = "fail";
                    }
                }
                var history = histories.stream().filter(h -> id.equals(h.get("control_id"))).toList();
                String state = automatic.equals("pass") ? history.isEmpty() ? "pending" : (String) history.get(0).get("decision") : automatic;
                counts.put(state, counts.get(state)+1);
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("id", id); row.put("name", control.path("name").asText()); row.put("evidence", control.path("evidence").asText());
                row.put("checks", checks); row.put("automaticStatus", codes.isEmpty() ? "manual" : automatic);
                row.put("status", state); row.put("revision", history.isEmpty() ? 0 : history.get(0).get("revision")); row.put("history", history);
                controls.add(row);
            }
            coverage.put("controls", controls); coverage.put("counts", counts); coverage.put("templateId", templateId);
            coverage.put("packageId", template.get("package_id")); coverage.put("version", template.get("version")); coverage.put("contentSha256", template.get("content_sha256"));
            coverage.put("complete", counts.get("pending") == 0 && counts.get("error") == 0);
            profiles.add(coverage);
        }
        return profiles;
    }

    @Transactional
    public List<Map<String, Object>> review(long taskId, String agentId, Decision body, Long reviewer) {
        if (reviewer == null || reviewer <= 0 || body == null || body.revision() < 0 || body.revision() >= 10000
                || !Set.of("pass", "fail", "not_applicable", "pending").contains(Objects.toString(body.decision(), "")))
            throw new IllegalArgumentException("条款复核请求无效");
        // Same task lock as result ingestion: decisions cannot race the first report.
        if (jdbc.update("UPDATE t_baseline_task SET progress=progress WHERE id=?", taskId) != 1)
            throw new IllegalArgumentException("任务不存在");
        var profile = assessment(taskId, agentId).stream().filter(p -> ((Number) p.get("templateId")).longValue() == body.templateId()).findFirst()
                .orElseThrow(() -> new IllegalArgumentException("主机没有该合规包快照"));
        @SuppressWarnings("unchecked") var controls = (List<Map<String, Object>>) profile.get("controls");
        var control = controls.stream().filter(c -> c.get("id").equals(body.controlId())).findFirst()
                .orElseThrow(() -> new IllegalArgumentException("条款不在快照范围内"));
        if (((Number) control.get("revision")).intValue() != body.revision()) throw new IllegalArgumentException("复核记录已更新，请刷新后再提交");
        if (Set.of("pass", "not_applicable").contains(body.decision()) && !Set.of("manual", "pass").contains(control.get("automaticStatus")))
            throw new IllegalArgumentException("自动证据未通过或未完整收齐，不能确认通过或不适用");
        String note = bounded(body.note(), 4000), ref = bounded(body.evidenceRef(), 1024);
        if (note.length() < 10 || !body.decision().equals("pending") && ref.isBlank())
            throw new IllegalArgumentException("请填写至少 10 字的复核依据和证据索引；不适用须说明适用性判断");
        jdbc.update("""
                INSERT INTO t_baseline_compliance_review(task_id,agent_id,template_id,control_id,revision,decision,note,evidence_ref,reviewed_by)
                VALUES (?,?,?,?,?,?,?,?,?)
                """, taskId, agentId, body.templateId(), body.controlId(), body.revision()+1, body.decision(), note, ref, reviewer);
        return assessment(taskId, agentId);
    }

    private static String bounded(String text, int max) {
        if (text == null) return "";
        if (text.length() > max || text.codePoints().anyMatch(c -> Character.isISOControl(c) && c != '\n' && c != '\r' && c != '\t'))
            throw new IllegalArgumentException("复核文字过长或含控制字符");
        return text.trim();
    }
}
