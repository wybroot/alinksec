package com.alinksec.service.baseline;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.*;

/** Reviewed clause inventory, compiled independently of imported package claims. */
public final class BaselineComplianceCatalog {
    private static final JsonNode ROOT;
    static {
        try (var input = BaselineComplianceCatalog.class.getResourceAsStream("/baseline/compliance-catalog.json")) {
            ROOT = new ObjectMapper().readTree(Objects.requireNonNull(input));
        } catch (Exception e) { throw new ExceptionInInitializerError(e); }
    }
    private BaselineComplianceCatalog() {}

    public static Map<String, String> windowsReferences() {
        Map<String, String> result = new HashMap<>();
        ROOT.path("windowsReferences").fields().forEachRemaining(e -> result.put(e.getKey(), e.getValue().asText()));
        return Map.copyOf(result);
    }

    public static JsonNode catalog(String id) {
        for (var catalog : ROOT.path("catalogs")) if (catalog.path("id").asText().equals(id)) return catalog.deepCopy();
        throw new IllegalArgumentException("合规条款目录未知，请更新服务端后再导入");
    }

    public static void validate(JsonNode document) {
        JsonNode compliance = document.path("compliance");
        require(compliance.isObject() && compliance.size() == 3 && compliance.has("catalogId") && compliance.has("catalogSha256") && compliance.has("controlChecks"), "合规包需指定条款目录、摘要及完整映射");
        require(compliance.path("catalogId").isTextual(), "合规目录编号无效");
        JsonNode catalog = catalog(compliance.path("catalogId").asText());
        try {
            String digest = HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(
                    com.alinksec.common.util.JsonUtils.write(BaselinePackageFormat.canonical(catalog)).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            require(digest.equals(compliance.path("catalogSha256").asText()), "合规条款目录摘要不一致");
        } catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
        require(document.path("standard").equals(catalog.path("standard")), "合规包标准与目录不一致");
        require(document.path("unsupported").isEmpty(), "完整合规包需为全部条款提供检查或人工核验要求");
        JsonNode mappings = compliance.path("controlChecks");
        require(mappings.isObject() && mappings.size() == catalog.path("controls").size(), "合规条款映射不完整");
        String os = document.path("osType").asInt() == 1 ? "linux" : "windows";
        Set<String> items = new HashSet<>(), referenced = new HashSet<>();
        document.path("items").forEach(item -> items.add(item.path("code").asText()));
        JsonNode contracts = catalog.path("evidenceChecks").path(os);
        Map<String, JsonNode> definitions = new HashMap<>();
        document.path("items").forEach(item -> definitions.put(item.path("code").asText(), item.path("check")));
        contracts.fields().forEachRemaining(entry -> {
            JsonNode actual = definitions.get(entry.getKey());
            require(actual != null, "合规包缺少目录定义的自动证据");
            var expected = entry.getValue().deepCopy();
            var observed = actual.deepCopy();
            // Runtime bounds remain validated by the base format. SSH connection
            // context is intentionally site supplied and stays in task evidence.
            ((com.fasterxml.jackson.databind.node.ObjectNode) expected).remove("timeout_ms");
            ((com.fasterxml.jackson.databind.node.ObjectNode) observed).remove("timeout_ms");
            if (expected.path("type").asText().equals("sshd_effective")) {
                ((com.fasterxml.jackson.databind.node.ObjectNode) expected).remove("connection");
                ((com.fasterxml.jackson.databind.node.ObjectNode) observed).remove("connection");
            }
            require(expected.equals(observed), "合规包修改了目录必需证据的核查含义: " + entry.getKey());
        });
        for (var control : catalog.path("controls")) {
            JsonNode checks = mappings.path(control.path("id").asText());
            require(checks.isArray() && checks.size() <= 500, "合规条款缺少检查映射");
            Set<String> seen = new HashSet<>();
            for (var code : checks) {
                require(code.isTextual() && items.contains(code.asText()) && seen.add(code.asText()), "合规条款引用未知或重复检查");
                referenced.add(code.asText());
            }
            for (var required : control.path("requiredChecks").path(os))
                require(seen.contains(required.asText()), "合规包遗漏必需自动证据: " + required.asText());
        }
        require(referenced.equals(items), "合规包存在未映射检查");
    }

    public static Map<String, Object> coverage(JsonNode document) {
        if (!document.has("compliance")) return Map.of();
        var catalog = catalog(document.path("compliance").path("catalogId").asText());
        List<Map<String, Object>> controls = new ArrayList<>();
        int withChecks = 0;
        for (var control : catalog.path("controls")) {
            var checks = document.path("compliance").path("controlChecks").path(control.path("id").asText());
            if (!checks.isEmpty()) withChecks++;
            controls.add(Map.of("id", control.path("id").asText(), "name", control.path("name").asText(),
                    "evidence", control.path("evidence").asText(), "checkCodes", checks,
                    "mode", checks.isEmpty() ? "manual" : "hybrid"));
        }
        return Map.of("catalogId", catalog.path("id").asText(), "scope", catalog.path("scope").asText(),
                "standardUrl", ROOT.path("standardUrl").asText(), "scopeNote", ROOT.path("scopeNote").asText(),
                "total", controls.size(), "withAutomaticEvidence", withChecks, "manualOnly", controls.size()-withChecks,
                "controls", controls);
    }
    private static void require(boolean value, String message) {
        if (!value) throw new IllegalArgumentException(message);
    }
}
