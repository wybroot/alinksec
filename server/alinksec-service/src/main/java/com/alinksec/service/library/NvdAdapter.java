package com.alinksec.service.library;

import com.alinksec.common.util.JsonUtils;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.List;

/** Keeps NVD metadata; only explicit mappings and simple OR applicability become scan rules. */
public final class NvdAdapter {
    private NvdAdapter() {}
    public static JsonNode normalize(JsonNode cve, List<LibraryProperties.Product> products) {
        ObjectNode result = JsonUtils.mapper().createObjectNode();
        String id = cve.path("id").asText();
        result.put("cve_id", id);
        String description = id;
        for (JsonNode text : cve.path("descriptions")) if ("en".equals(text.path("lang").asText())) { description = text.path("value").asText(id); break; }
        result.put("title", description.substring(0, Math.min(512, description.length())));
        result.put("description", description);
        double score = 0;
        for (String metric : List.of("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")) {
            JsonNode values = cve.path("metrics").path(metric);
            if (!values.isEmpty()) { score = values.get(0).path("cvssData").path("baseScore").asDouble(); break; }
        }
        result.put("cvss", score);
        result.put("severity", score >= 9 ? 4 : score >= 7 ? 3 : score >= 4 ? 2 : 1);
        String published = cve.path("published").asText("");
        if (!published.isEmpty()) result.put("published_at", published.endsWith("Z") ? published : published + "Z");
        ArrayNode affected = result.putArray("affected");
        if (!"Rejected".equals(cve.path("vulnStatus").asText())) {
            for (JsonNode config : cve.path("configurations")) {
                if (config.path("negate").asBoolean() || "AND".equals(config.path("operator").asText())) continue;
                for (JsonNode node : config.path("nodes")) {
                    if (node.path("negate").asBoolean() || "AND".equals(node.path("operator").asText()) || node.has("children")) continue;
                    for (JsonNode match : node.path("cpeMatch")) {
                        if (!match.path("vulnerable").asBoolean()) continue;
                        String cpe = match.path("criteria").asText("");
                        for (var product : products) {
                            if (!cpe.startsWith(product.getCpePrefix())) continue;
                            ObjectNode rule = JsonUtils.mapper().createObjectNode();
                            rule.put("name", product.getName()); rule.put("match", "exact");
                            rule.put("os", product.getOs()); rule.put("source", product.getAssetSource());
                            ArrayNode ranges = rule.putArray("ranges");
                            for (String key : List.of("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding")) {
                                if (match.hasNonNull(key)) {
                                    String op = switch (key) { case "versionStartIncluding" -> ">="; case "versionStartExcluding" -> ">"; case "versionEndIncluding" -> "<="; default -> "<"; };
                                    ranges.add(op + match.path(key).asText());
                                }
                            }
                            if (ranges.isEmpty()) {
                                String[] parts = cpe.split(":", -1);
                                if (parts.length > 5 && !List.of("*", "-").contains(parts[5])) ranges.add("=" + parts[5]);
                            }
                            // An upstream version boundary is not a guaranteed vendor patch version.
                            rule.put("fixed_version", "");
                            if (!ranges.isEmpty()) affected.add(rule);
                        }
                    }
                }
            }
        }
        result.put("upstream", "nvd");
        return result;
    }
}
