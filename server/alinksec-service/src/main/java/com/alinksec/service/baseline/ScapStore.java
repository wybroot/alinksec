package com.alinksec.service.baseline;

import com.alinksec.common.util.JsonUtils;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.jdbc.core.JdbcTemplate;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class ScapStore {
    private ScapStore() {}
    static final Set<String> OUTCOMES = Set.of("pass","fail","error","unknown","notapplicable","notchecked","notselected","informational","fixed");
    static final Set<String> ISSUES = Set.of("","scap_disabled","scap_unsupported","scap_config_invalid","scap_runtime_unavailable",
            "scap_runtime_changed","scap_engine_version","scap_resource_limit","scap_timeout","scap_worker_failed","scap_worker_protocol",
            "scap_archive_limit","scap_archive_invalid","scap_archive_path","scap_manifest_invalid","scap_xml_invalid","scap_xml_external_entity",
            "scap_xml_limit","scap_reference_missing","scap_reference_external","scap_executable_content","scap_check_system_unsupported",
            "scap_selection_invalid","scap_content_unresolved","scap_rule_invalid","scap_profile_invalid","scap_result_invalid","scap_result_missing","scap_result_limit",
            "scap_native_failed","scap_cancelled","scap_busy","scap_command_invalid","command_failed","command_timeout","task_timeout");
    static boolean hash(String value) { return value != null && value.matches("[0-9a-f]{64}"); }
    static String digest(String value) { return ScapPackage.digest(value.getBytes(StandardCharsets.UTF_8)); }
    static void actor(Long actor) { if (actor == null || actor <= 0) throw new IllegalArgumentException("缺少操作人身份"); }
    static String note(String note) {
        if (note == null || note.isBlank() || note.length() > 2000) throw new IllegalArgumentException("请填写 1 至 2000 字说明");
        return note.strip();
    }
    static Map<String,Object> one(JdbcTemplate jdbc, String sql, Object... args) {
        var rows = jdbc.queryForList(sql,args);
        if (rows.size() != 1) throw new IllegalArgumentException("SCAP 内容或任务不存在");
        return rows.get(0);
    }
    static void gate(JdbcTemplate jdbc, String code) {
        jdbc.update("INSERT INTO t_scap_package_gate(code) VALUES (?) ON CONFLICT(code) DO NOTHING",code);
        jdbc.update("UPDATE t_scap_package_gate SET revision=revision+1 WHERE code=?",code);
    }
    static String metadata(ScapPackage content) {
        Map<String,Object> metadata = new LinkedHashMap<>();
        metadata.put("manifest",content.manifest()); metadata.put("rules",content.rules()); metadata.put("profiles",content.profiles());
        return JsonUtils.write(metadata);
    }
    static ScapPackage packageContent(Map<String,Object> row) {
        String encoded = String.valueOf(row.get("content_zip"));
        if (encoded.length() > 3*1024*1024) throw new IllegalArgumentException("SCAP 内容超出存储边界");
        ScapPackage content;
        try { content=ScapPackage.read(Base64.getDecoder().decode(encoded)); }
        catch (RuntimeException e) { throw new IllegalArgumentException("SCAP 已保存内容无效，请重新导入"); }
        if (!content.sha256().equals(row.get("content_sha256")) || !hash(String.valueOf(row.get("source_sha256")))
                || !JsonUtils.read(metadata(content)).equals(JsonUtils.read(String.valueOf(row.get("metadata")))))
            throw new IllegalArgumentException("SCAP 内容或审核元数据摘要不匹配");
        var m=content.manifest();
        String original=row.get("source_zip").toString();
        if (original.length()>3*1024*1024) throw new IllegalArgumentException("SCAP 原始内容无效");
        var source=ScapPackage.read(Base64.getDecoder().decode(original));
        var resolution=JsonUtils.read(row.get("resolution").toString());
        if (!ScapPackage.digest(Base64.getDecoder().decode(original)).equals(row.get("source_sha256"))||!source.manifest().equals(m)
                || !source.sha256().equals(resolution.path("sourceCanonicalSha256").asText())) throw new IllegalArgumentException("SCAP 原始内容和标准解析来源不匹配");
        for (var field:Map.of("code","code","version","version","name","name","os_version_pattern","osVersionPattern").entrySet())
            if (!m.path(field.getValue()).asText().equals(row.get(field.getKey()))) throw new IllegalArgumentException("SCAP 内容身份不匹配");
        if (((Number)row.get("os_type")).intValue()!=m.path("osType").intValue()) throw new IllegalArgumentException("SCAP 系统身份不匹配");
        return content;
    }
    static JsonNode taskSnapshot(Map<String,Object> task) {
        String snapshot=String.valueOf(task.get("snapshot"));
        if (!digest(snapshot).equals(task.get("snapshot_sha256"))) throw new IllegalArgumentException("SCAP 任务快照摘要不匹配");
        JsonNode metadata=JsonUtils.read(snapshot);
        String encoded=String.valueOf(task.get("content_zip"));
        if (encoded.length()>3*1024*1024) throw new IllegalArgumentException("SCAP 任务内容无效");
        String contentHash=ScapPackage.digest(Base64.getDecoder().decode(encoded));
        if (!contentHash.equals(task.get("content_sha256")) || !contentHash.equals(metadata.path("contentSha256").asText()))
            throw new IllegalArgumentException("SCAP 任务内容与快照不匹配");
        return metadata;
    }
    static void advance(JdbcTemplate jdbc,String task) {
        var rows=jdbc.queryForList("SELECT state,count(*) AS total FROM t_scap_task_agent WHERE task_id=? GROUP BY state",task);
        if (rows.isEmpty()) return;
        boolean pending=rows.stream().anyMatch(row->row.get("state").equals("pending"));
        boolean failed=rows.stream().anyMatch(row->!List.of("pending","complete").contains(row.get("state")));
        if (!pending) jdbc.update("UPDATE t_scap_task SET state=?,finished_at=CURRENT_TIMESTAMP WHERE id=?",failed?"partial":"complete",task);
    }
}
