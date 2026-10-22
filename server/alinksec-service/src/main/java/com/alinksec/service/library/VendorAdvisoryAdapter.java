package com.alinksec.service.library;

import com.alinksec.service.scan.PackageVersions;
import com.alinksec.service.scan.VulnerabilityEvidence;
import com.alinksec.service.scan.VulnerabilityScope;
import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import java.io.*;
import java.util.zip.GZIPInputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;

/** Publisher formats are parsed as data. A fixed version never implies that every earlier version is affected. */
public final class VendorAdvisoryAdapter {
    public static final Set<String> TYPES = Set.of("ubuntu-usn", "debian-tracker", "redhat-csaf", "msrc-cvrf");
    private static final ObjectMapper JSON = new ObjectMapper(JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(40)
                    .maxStringLength(2 << 20).maxNumberLength(64).build()).build());
    public record Document(String id, String publisher, String title, String version,
                           Instant updated, List<JsonNode> cves) {}
    private VendorAdvisoryAdapter() {}

    public static Document parse(LibraryProperties.Source source, byte[] raw) throws IOException {
        if (!TYPES.contains(source.getType()) || raw.length == 0 || raw.length > (32 << 20))
            throw invalid();
        if ("debian-tracker".equals(source.getType())) return debian(source, raw);
        JsonNode root;
        try (var parser = JSON.createParser(raw)) {
            root = JSON.readTree(parser);
            if (root == null || !root.isObject() || parser.nextToken() != null) throw invalid();
        }
        return switch (source.getType()) {
            case "ubuntu-usn" -> ubuntu(root);
            case "redhat-csaf" -> redhat(source, root);
            case "msrc-cvrf" -> microsoft(root);
            default -> throw invalid();
        };
    }

    public static Instant timestamp(String value) {
        try {
            // These publisher APIs also serialize UTC database dates without the trailing Z.
            if (value.matches("[0-9]{4}-[0-9T:.-]+")) value += "Z";
            return OffsetDateTime.parse(value).toInstant();
        } catch (RuntimeException e) { throw invalid(); }
    }

    private static Document ubuntu(JsonNode root) {
        String id = required(root, "id", 64);
        if (!id.matches("USN-[0-9]{1,8}-[0-9]{1,4}") || !root.path("release_packages").isObject()
                || !root.path("cves_ids").isArray()) throw invalid();
        var builder = new Builder(id, "Canonical", text(root, "title", 512), "",
                timestamp(required(root, "published", 128)));
        var facts = JSON.createArrayNode();
        var releases = root.path("release_packages").fields();
        int count = 0;
        while (releases.hasNext()) {
            var release = releases.next();
            if (!release.getKey().matches("[a-z][a-z0-9-]{0,63}") || !release.getValue().isArray()) throw invalid();
            for (var pkg : release.getValue()) {
                if (++count > 1000 || !pkg.path("is_source").isBoolean()) throw invalid();
                ObjectNode fact = facts.addObject();
                fact.put("release", release.getKey());
                fact.put("package", required(pkg, "name", 255));
                fact.put("fixed_version", required(pkg, "version", 255));
                fact.put("package_scope", pkg.path("is_source").asBoolean() ? "source" : "binary");
                fact.put("pocket", text(pkg, "pocket", 128));
            }
        }
        String description = text(root, "description", 8192);
        for (var cve : root.path("cves_ids")) {
            String cveId = cve.asText();
            ObjectNode document = builder.cve(cveId, description, 0);
            var meta = document.withArray("vendor_advisories").addObject();
            meta.put("advisory_id", id);
            meta.put("url", "https://ubuntu.com/security/notices/" + id);
            meta.put("scope", "Notice lists fixed packages; per-CVE affected release, architecture and earlier-version boundaries are not inferred.");
            meta.set("packages", facts);
        }
        return builder.finish();
    }

    private static Document debian(LibraryProperties.Source source, byte[] raw) throws IOException {
        if (source.getVendorPackages().isEmpty()) throw invalid();
        var selected = Set.copyOf(source.getVendorPackages());
        var builder = new Builder("tracker", "Debian Security Team", "Debian Security Tracker", "",
                Instant.EPOCH);
        var seen = new HashSet<String>();
        InputStream decoded = new ByteArrayInputStream(raw);
        if (raw.length > 2 && raw[0] == (byte) 0x1f && raw[1] == (byte) 0x8b) decoded = new GZIPInputStream(decoded);
        try (var parser = JSON.createParser(new InflatedLimit(decoded))) {
            if (parser.nextToken() != JsonToken.START_OBJECT) throw invalid();
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                if (parser.currentToken() != JsonToken.FIELD_NAME) throw invalid();
                String pkg = parser.currentName();
                if (!seen.add(pkg)) throw invalid();
                if (parser.nextToken() != JsonToken.START_OBJECT) throw invalid();
                if (!selected.contains(pkg)) { parser.skipChildren(); continue; }
                JsonNode issues = JSON.readTree(parser);
                var fields = issues.fields();
                while (fields.hasNext()) {
                    var issue = fields.next();
                    if (!issue.getKey().matches("CVE-[0-9]{4}-[0-9]{4,19}")) continue;
                    ObjectNode document = builder.cve(issue.getKey(), text(issue.getValue(), "description", 8192), 0);
                    JsonNode releaseMap = issue.getValue().path("releases");
                    if (!releaseMap.isObject()) throw invalid();
                    var releaseFields = releaseMap.fields();
                    while (releaseFields.hasNext()) {
                        var release = releaseFields.next();
                        ObjectNode fact = document.withArray("vendor_advisories").addObject();
                        if (document.path("vendor_advisories").size() > 200) throw invalid();
                        fact.put("advisory_id", issue.getKey());
                        fact.put("url", "https://security-tracker.debian.org/tracker/" + issue.getKey());
                        fact.put("package_scope", "source");
                        fact.put("package", pkg);
                        fact.put("release", release.getKey());
                        fact.put("status", text(release.getValue(), "status", 64));
                        fact.put("fixed_version", text(release.getValue(), "fixed_version", 255));
                        fact.put("urgency", text(release.getValue(), "urgency", 64));
                        fact.put("scope", "Source package status is retained; no binary-package identity or patch version is invented.");
                    }
                }
            }
            if (parser.nextToken() != null) throw invalid();
        }
        return builder.finish();
    }

    /** The large full tracker is streamed; unselected source-package records are not materialized. */
    private static final class InflatedLimit extends FilterInputStream {
        private long count;
        InflatedLimit(InputStream in) { super(in); }
        private void add(long size) throws IOException { if (size > 0 && (count += size) > (256L << 20)) throw new IOException("Tracker inflated size limit"); }
        @Override public int read() throws IOException { int value = in.read(); if (value >= 0) add(1); return value; }
        @Override public int read(byte[] bytes, int offset, int length) throws IOException { int size = in.read(bytes, offset, length); add(size); return size; }
    }

    private static Document redhat(LibraryProperties.Source source, JsonNode root) {
        JsonNode header = root.path("document"), tracking = header.path("tracking");
        String id = required(tracking, "id", 128);
        if (!id.matches("RHSA-[0-9]{4}:[0-9]{1,12}") || !"2.0".equals(header.path("csaf_version").asText())
                || !root.path("vulnerabilities").isArray()) throw invalid();
        var builder = new Builder(id, "Red Hat", text(header, "title", 512),
                required(tracking, "version", 128), timestamp(required(tracking, "current_release_date", 128)));
        var products = new LinkedHashMap<String, JsonNode>();
        collectProducts(root.path("product_tree").path("branches"), products, 0);
        var relationships = new HashMap<String, JsonNode>();
        for (var relationship : root.path("product_tree").path("relationships")) {
            String key = required(relationship.path("full_product_name"), "product_id", 255);
            if (relationships.put(key, relationship) != null || relationships.size() > 10_000) throw invalid();
        }
        var mappings = new HashMap<String, LibraryProperties.VendorProduct>();
        for (var mapping : source.getVendorProducts()) mappings.put(mapping.getProductId(), mapping);
        for (var vulnerability : root.path("vulnerabilities")) {
            String cve = required(vulnerability, "cve", 32);
            double score = 0;
            for (var metric : vulnerability.path("scores")) {
                for (String version : List.of("cvss_v4", "cvss_v3", "cvss_v2"))
                    if (metric.path(version).has("baseScore")) score = Math.max(score, checkedScore(metric.path(version).path("baseScore")));
            }
            String description = "";
            for (var note : vulnerability.path("notes"))
                if ("description".equals(note.path("category").asText())) { description = text(note, "text", 8192); break; }
            ObjectNode document = builder.cve(cve, description, score);
            var statusFields = vulnerability.path("product_status").fields();
            int statusCount = 0;
            while (statusFields.hasNext()) {
                var status = statusFields.next();
                if (!status.getValue().isArray()) throw invalid();
                for (var productId : status.getValue()) {
                    if (++statusCount > 1000 || !productId.isTextual()) throw invalid();
                    String product = productId.asText();
                    ObjectNode fact = document.withArray("vendor_advisories").addObject();
                    fact.put("advisory_id", id); fact.put("url", "https://access.redhat.com/errata/" + id);
                    fact.put("product_id", product); fact.put("status", status.getKey());
                    JsonNode relationship = relationships.get(product);
                    if (relationship == null || !Set.of("default_component_of", "installed_on")
                            .contains(relationship.path("category").asText())) continue;
                    String packageId = relationship.path("product_reference").asText();
                    String platformId = relationship.path("relates_to_product_reference").asText();
                    var mapping = mappings.get(platformId);
                    JsonNode pkg = products.get(packageId);
                    if (pkg != null) fact.put("package", pkg.path("name").asText());
                    if (mapping == null || pkg == null) continue;
                    NativeRpm identity = nativeRpm(pkg);
                    if (identity == null) continue;
                    // Fixed-only assertions prove this exact fixed package, not an invented <fixed affected range.
                    String assessment = switch (status.getKey()) {
                        case "known_affected" -> "affected";
                        case "known_not_affected", "fixed" -> "not_affected";
                        default -> "";
                    };
                    if (assessment.isEmpty()) continue;
                    var rule = document.withArray("affected").addObject();
                    rule.put("name", identity.name()); rule.put("source", "rpm");
                    rule.put("version_scheme", "rpm"); rule.put("match", "exact");
                    rule.put("distro_id", mapping.getDistroId()); rule.put("distro_version", mapping.getDistroVersion());
                    rule.put("architecture", identity.arch()); rule.put("vrange", "=" + identity.version());
                    rule.put("fixed_version", "");
                    var evidence = rule.putObject("evidence");
                    evidence.put("basis", "vendor_advisory"); evidence.put("assessment", assessment);
                    evidence.put("package_scope", "binary"); evidence.put("publisher", "Red Hat");
                    evidence.put("advisory_id", id); evidence.put("url", "https://access.redhat.com/errata/" + id);
                    evidence.put("notes", "CSAF " + status.getKey() + " for exact binary EVR and publisher product " + platformId
                            + "; configured distribution identity; no lower-version applicability or repair target inferred.");
                }
            }
        }
        return builder.finish();
    }

    private record NativeRpm(String name, String version, String arch) {}
    private static NativeRpm nativeRpm(JsonNode product) {
        String name = product.path("name").asText();
        String purl = product.path("product_identification_helper").path("purl").asText();
        if (!purl.startsWith("pkg:rpm/redhat/") || purl.contains("#") || purl.length() > 2048) return null;
        try {
            int at = purl.indexOf('@'), query = purl.indexOf('?');
            if (at < 15 || query < at) return null;
            String packageName = decode(purl.substring("pkg:rpm/redhat/".length(), at));
            String purlVersion = decode(purl.substring(at + 1, query));
            var qualifiers = new HashMap<String, String>();
            for (String item : purl.substring(query + 1).split("&")) {
                int equals = item.indexOf('=');
                if (equals < 1 || qualifiers.put(decode(item.substring(0, equals)), decode(item.substring(equals + 1))) != null) return null;
            }
            String arch = qualifiers.getOrDefault("arch", "");
            if (!VulnerabilityScope.architecture(arch) || Set.of("src", "nosrc").contains(arch)
                    || !name.startsWith(packageName + "-") || !name.endsWith("." + arch)) return null;
            String version = name.substring(packageName.length() + 1, name.length() - arch.length() - 1);
            String epoch = qualifiers.get("epoch");
            if (epoch != null) purlVersion = epoch + ":" + purlVersion;
            if (PackageVersions.compare("rpm", version, purlVersion) != 0) return null;
            return new NativeRpm(packageName, version, arch);
        } catch (IllegalArgumentException e) { return null; }
    }
    private static String decode(String value) {
        return URLDecoder.decode(value.replace("+", "%2B"), StandardCharsets.UTF_8);
    }
    private static void collectProducts(JsonNode branches, Map<String, JsonNode> products, int depth) {
        if (depth > 16) throw invalid();
        if (!branches.isMissingNode() && !branches.isArray()) throw invalid();
        for (var branch : branches) {
            if (branch.has("product")) {
                var product = branch.path("product");
                if (products.put(required(product, "product_id", 255), product) != null || products.size() > 10_000) throw invalid();
            }
            collectProducts(branch.path("branches"), products, depth + 1);
        }
    }

    private static Document microsoft(JsonNode root) {
        JsonNode tracking = root.path("DocumentTracking");
        String id = VendorAdvisoryIndex.monthId(required(tracking.path("Identification").path("ID"), "Value", 128));
        if (!root.path("Vulnerability").isArray()) throw invalid();
        var builder = new Builder(id, "Microsoft", text(root.path("DocumentTitle"), "Value", 512),
                text(tracking, "Version", 128), timestamp(required(tracking, "CurrentReleaseDate", 128)));
        for (var vulnerability : root.path("Vulnerability")) {
            String cve = required(vulnerability, "CVE", 32);
            double score = 0;
            for (var metric : vulnerability.path("CVSSScoreSets"))
                if (metric.has("BaseScore")) score = Math.max(score, checkedScore(metric.path("BaseScore")));
            ObjectNode document = builder.cve(cve, text(vulnerability.path("Title"), "Value", 512), score);
            document.put("title", text(vulnerability.path("Title"), "Value", 512));
            ObjectNode fact = document.withArray("vendor_advisories").addObject();
            fact.put("advisory_id", id); fact.put("url", "https://msrc.microsoft.com/update-guide/vulnerability/" + cve);
            fact.put("scope", "Publisher product and KB/build identifiers are metadata; no installed Windows applicability, supersedence or patch verification is inferred.");
            ArrayNode statuses = fact.putArray("product_statuses");
            for (var status : vulnerability.path("ProductStatuses")) {
                var item = statuses.addObject();
                item.put("type", status.path("Type").asInt(-1));
                item.set("products", boundedStrings(status.path("ProductID"), 500));
            }
            ArrayNode fixes = fact.putArray("remediations");
            for (var remediation : vulnerability.path("Remediations")) {
                if (fixes.size() >= 500) throw invalid();
                var item = fixes.addObject();
                item.put("type", remediation.path("Type").asInt(-1));
                item.put("description", text(remediation.path("Description"), "Value", 512));
                item.put("fixed_build", text(remediation, "FixedBuild", 255));
                item.put("subtype", text(remediation, "SubType", 128));
                item.set("products", boundedStrings(remediation.path("ProductID"), 500));
            }
        }
        return builder.finish();
    }
    private static double checkedScore(JsonNode value) {
        double score=value.asDouble(-1);
        if (!value.isNumber() || !Double.isFinite(score) || score<0 || score>10) throw invalid();
        return score;
    }
    private static ArrayNode boundedStrings(JsonNode values, int maximum) {
        if (values.isMissingNode() || values.isNull()) return JSON.createArrayNode();
        if (!values.isArray() || values.size() > maximum) throw invalid();
        ArrayNode result = JSON.createArrayNode();
        for (var value : values) {
            if (!value.isTextual() || value.asText().length() > 255) throw invalid();
            result.add(value.asText());
        }
        return result;
    }
    private static String required(JsonNode node, String field, int max) {
        if (!node.path(field).isTextual() || node.path(field).asText().isBlank()
                || node.path(field).asText().length() > max) throw invalid();
        return node.path(field).asText();
    }
    private static String text(JsonNode node, String field, int max) {
        JsonNode value = node.path(field);
        if (value.isMissingNode() || value.isNull()) return "";
        if (!value.isTextual()) throw invalid();
        String text = value.asText();
        return text.substring(0, Math.min(text.length(), max));
    }
    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("厂商原生公告格式、身份或容量校验失败");
    }
    private static final class Builder {
        final String id, publisher, title, version;
        final Instant updated;
        final Map<String, ObjectNode> documents = new LinkedHashMap<>();
        Builder(String id, String publisher, String title, String version, Instant updated) {
            this.id=id; this.publisher=publisher; this.title=title; this.version=version; this.updated=updated;
        }
        ObjectNode cve(String cve, String description, double score) {
            if (!cve.matches("CVE-[0-9]{4}-[0-9]{4,19}")
                    || !Double.isFinite(score) || score < 0 || score > 10) throw invalid();
            ObjectNode existing = documents.get(cve);
            if (existing != null) return existing;
            if (documents.size() >= 10_000) throw invalid();
            ObjectNode node = JSON.createObjectNode();
            node.put("cve_id", cve); node.put("title", title.isBlank() ? cve : title);
            node.put("description", description); node.put("cvss", score);
            node.put("severity", score >= 9 ? 4 : score >= 7 ? 3 : score >= 4 ? 2 : 1);
            node.put("score_status", score == 0 ? "not_provided" : "publisher_score");
            node.putArray("affected"); node.putArray("vendor_advisories");
            documents.put(cve, node);
            return node;
        }
        Document finish() {
            long total = 0;
            for (var node : documents.values()) {
                LibraryCatalog.validateCve(node);
                total += VulnerabilityEvidence.canonicalJson(node).getBytes(StandardCharsets.UTF_8).length;
                if (total > (32 << 20)) throw invalid();
            }
            return new Document(id,publisher,title,version,updated,List.copyOf(documents.values()));
        }
    }
}
