package com.alinksec.service.library;

import com.alinksec.service.scan.VulnerabilityEvidence;
import com.alinksec.service.scan.VulnerabilityScope;
import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.databind.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

/** Discovery paths come from validated native identities, never arbitrary URLs in a remote document. */
final class VendorAdvisoryIndex {
    static final Map<String,String> DEFAULTS = Map.of(
            "ubuntu-usn", "https://ubuntu.com/security",
            "debian-tracker", "https://security-tracker.debian.org/tracker/data/json",
            "redhat-csaf", "https://security.access.redhat.com/data/csaf/v2/advisories",
            "msrc-cvrf", "https://api.msrc.microsoft.com/cvrf/v3.0");
    static final ObjectMapper JSON = new ObjectMapper(JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(40).maxStringLength(2 << 20).build()).build());
    static final String MONTH_ID="[0-9]{4}-(?i:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)(?:-[A-Z])?";
    static String monthId(String id) {
        if (!id.matches(MONTH_ID)) throw invalid();
        return id.substring(0,5)+id.substring(5,6).toUpperCase(Locale.ROOT)+id.substring(6,8).toLowerCase(Locale.ROOT)+id.substring(8);
    }
    record Candidate(String id, String address, Instant updated) {}
    static String address(LibraryProperties.Source source) {
        return source.getUrl().isBlank() ? DEFAULTS.get(source.getType()) : source.getUrl().replaceAll("/+$", "");
    }
    static void validate(LibraryProperties.Source source) {
        if (!VendorAdvisoryAdapter.TYPES.contains(source.getType())) throw invalid();
        URI uri = FeedDownload.validateAddress(address(source));
        if (uri.getQuery() != null || uri.getRawPath().contains("%") || uri.getPath().contains("..")
                || !source.getApiKey().isBlank() || source.getVendorPages() < 1 || source.getVendorPages() > 10
                || source.getVendorPackages().size() > 100 || source.getVendorProducts().size() > 100) throw invalid();
        Set<String> packages = new HashSet<>(), products = new HashSet<>();
        for (String pkg : source.getVendorPackages())
            if (!pkg.matches("[a-z0-9][a-z0-9+.-]{0,254}") || !packages.add(pkg)) throw invalid();
        if ("debian-tracker".equals(source.getType()) && packages.isEmpty()) throw invalid();
        for (var product : source.getVendorProducts()) {
            if (!product.getProductId().matches("[A-Za-z0-9][A-Za-z0-9_.:+-]{0,254}")
                    || !products.add(product.getProductId()) || !VulnerabilityScope.distributionId(product.getDistroId())
                    || !VulnerabilityScope.distributionVersion(product.getDistroVersion())) throw invalid();
        }
    }
    static String fingerprint(LibraryProperties.Source source) {
        var products = source.getVendorProducts().stream().map(p -> Map.of("product", p.getProductId(),
                "distro", p.getDistroId(), "version", p.getDistroVersion()))
                .sorted(Comparator.comparing(p -> p.get("product"))).toList();
        return VulnerabilityEvidence.sha256(VulnerabilityEvidence.canonicalJson(JSON.valueToTree(Map.of(
                "type", source.getType(), "url", address(source), "packages", new TreeSet<>(source.getVendorPackages()),
                "products", products, "initialDays", source.getInitialDays(), "pages", source.getVendorPages()))));
    }
    static Candidate direct(LibraryProperties.Source source) {
        String address = address(source), path = URI.create(address).getPath();
        if ("debian-tracker".equals(source.getType())) return new Candidate("tracker", address, Instant.EPOCH);
        if ("ubuntu-usn".equals(source.getType()) && path.matches(".*/USN-[0-9]{1,8}-[0-9]{1,4}\\.json"))
            return new Candidate(path.substring(path.lastIndexOf('/') + 1, path.length() - 5), address, Instant.EPOCH);
        if ("redhat-csaf".equals(source.getType()) && path.matches(".*/[0-9]{4}/rhsa-[0-9]{4}_[0-9]{1,12}\\.json")) {
            String name = path.substring(path.lastIndexOf('/') + 1, path.length() - 5);
            return new Candidate(name.replace("rhsa-", "RHSA-").replace('_', ':'), address, Instant.EPOCH);
        }
        if ("msrc-cvrf".equals(source.getType()) && path.matches(".*/cvrf/"+MONTH_ID))
            return new Candidate(monthId(path.substring(path.lastIndexOf('/') + 1)), address, Instant.EPOCH);
        return null;
    }
    static JsonNode json(byte[] raw) throws java.io.IOException {
        try (var parser = JSON.createParser(raw)) {
            JsonNode node = JSON.readTree(parser);
            if (node == null || !node.isObject() || parser.nextToken() != null) throw invalid();
            return node;
        }
    }
    static List<Candidate> redhat(byte[] raw, String base, Instant cutoff) {
        Map<String,Candidate> result = new LinkedHashMap<>();
        String text = new String(raw, StandardCharsets.UTF_8);
        if (!Arrays.equals(raw, text.getBytes(StandardCharsets.UTF_8))) throw invalid();
        for (String line : text.split("\\r?\\n")) {
            if (line.isEmpty()) continue;
            if (line.length() > 512 || !line.matches("\"[0-9]{4}/rh(sa|ba|ea)-[0-9]{4}_[0-9]{1,12}\\.json\",\"[^\"]{1,64}\"")) throw invalid();
            int comma = line.indexOf(',');
            String path = line.substring(1, comma - 1), date = line.substring(comma + 2, line.length() - 1);
            Instant updated = VendorAdvisoryAdapter.timestamp(date);
            if (!path.contains("/rhsa-") || updated.isBefore(cutoff)) continue;
            String file = path.substring(5, path.length() - 5);
            String id = file.replace("rhsa-", "RHSA-").replace('_', ':');
            add(result, new Candidate(id, base + "/" + path, updated));
        }
        return List.copyOf(result.values());
    }
    static List<Candidate> microsoft(byte[] raw, String base, Instant cutoff) throws java.io.IOException {
        JsonNode rows = json(raw).path("value");
        if (!rows.isArray() || rows.size() > 4096) throw invalid();
        Map<String,Candidate> result = new LinkedHashMap<>();
        for (JsonNode row : rows) {
            String id = row.path("ID").asText();
            String canonicalId=monthId(id);
            Instant updated = VendorAdvisoryAdapter.timestamp(row.path("CurrentReleaseDate").asText());
            if (!updated.isBefore(cutoff)) add(result, new Candidate(canonicalId, base + "/cvrf/" + id, updated));
        }
        return List.copyOf(result.values());
    }
    static void add(Map<String,Candidate> result, Candidate candidate) {
        if (result.put(candidate.id(), candidate) != null || result.size() > 32768) throw invalid();
    }
    static IllegalArgumentException invalid() { return new IllegalArgumentException("厂商公告索引、范围或配置校验失败"); }
}
