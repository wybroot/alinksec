package com.alinksec.service.library;

import com.alinksec.common.util.JsonUtils;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.zip.*;

/** Validates the complete candidate before it can replace a working library. */
public record SignaturePackage(String version, Map<String, Hash> hashes, List<JsonNode> rules) {
    public record Hash(String sha256, String name, int severity) {}
    public static SignaturePackage read(Path path, LibraryProperties props) throws IOException {
        Map<String, byte[]> entries = new HashMap<>();
        Set<String> names = new HashSet<>();
        Path hashFile = Files.createTempFile(path.toAbsolutePath().getParent(), "hashes-", ".tmp");
        Map<String, Hash> hashes;
        JsonNode manifest;
        String version;
        try {
            long remaining = props.getMaxDownloadBytes();
            try (ZipInputStream zip = new ZipInputStream(Files.newInputStream(path))) {
                ZipEntry entry;
                while ((entry = zip.getNextEntry()) != null) {
                    String name = entry.getName();
                    if (!Set.of("manifest.json", "hashes.txt", "rules.json").contains(name) || !names.add(name)) {
                        throw new IllegalArgumentException("特征包包含非法或重复文件");
                    }
                    if ("hashes.txt".equals(name)) {
                        try (var out = Files.newOutputStream(hashFile)) {
                            byte[] buffer = new byte[8192]; int n;
                            while ((n = zip.read(buffer)) != -1) {
                                remaining -= n;
                                if (remaining < 0) throw new IllegalArgumentException("下载或解压大小超过上限");
                                out.write(buffer, 0, n);
                            }
                        }
                    } else {
                        byte[] bytes = readBounded(zip, Math.min(remaining, 2L << 20));
                        remaining -= bytes.length;
                        entries.put(name, bytes);
                    }
                }
            }
            if (!entries.containsKey("manifest.json")) throw new IllegalArgumentException("特征包缺少 manifest.json");
            manifest = JsonUtils.mapper().readTree(entries.get("manifest.json"));
            version = manifest.path("db_version").asText("");
            if (!version.matches("[A-Za-z0-9._-]{1,32}")) throw new IllegalArgumentException("特征库版本号非法");
            hashes = readHashes(Files.newInputStream(hashFile), props.getMaxHashes());
        } finally { Files.deleteIfExists(hashFile); }
        List<JsonNode> rules = new ArrayList<>();
        if (entries.containsKey("rules.json")) {
            JsonNode parsed = JsonUtils.mapper().readTree(entries.get("rules.json"));
            JsonNode list = parsed.path("rules");
            if (!list.isArray() || list.size() > 2000) throw new IllegalArgumentException("rules.json 格式或规则数量非法");
            Set<String> ruleNames = new HashSet<>();
            for (JsonNode rule : list) {
                validateRule(rule);
                if (!ruleNames.add(rule.path("name").asText())) throw new IllegalArgumentException("规则名重复");
                rules.add(rule);
            }
        }
        if (hashes.isEmpty() && rules.isEmpty()) throw new IllegalArgumentException("拒绝发布空特征库");
        if (manifest.has("hash_count") && manifest.path("hash_count").asInt(-1) != hashes.size()) throw new IllegalArgumentException("hash_count 与有效哈希数不一致");
        if (manifest.has("rule_count") && manifest.path("rule_count").asInt(-1) != rules.size()) throw new IllegalArgumentException("rule_count 与有效规则数不一致");
        return new SignaturePackage(version, hashes, rules);
    }
    public static Map<String, Hash> readHashes(InputStream input, int max) throws IOException {
        Map<String, Hash> hashes = new TreeMap<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8))) {
            String line;
            while ((line = readLine(reader)) != null) {
                if (line.length() > 4096) throw new IllegalArgumentException("哈希行过长");
                if (line.isBlank() || line.startsWith("#")) continue;
                String[] fields = line.trim().split("\\s+");
                if (fields.length < 1 || fields.length > 3 || !fields[0].matches("[a-fA-F0-9]{64}")) throw new IllegalArgumentException("SHA256 哈希格式非法");
                String name = fields.length > 1 ? fields[1] : "Malware.KnownHash";
                int severity = fields.length > 2 ? Integer.parseInt(fields[2]) : 4;
                Hash hash = checkedHash(fields[0], name, severity);
                hashes.put(hash.sha256(), hash);
                if (hashes.size() > max) throw new IllegalArgumentException("哈希库超过容量上限，已有库保留");
            }
        }
        return hashes;
    }
    private static String readLine(BufferedReader reader) throws IOException {
        StringBuilder text = new StringBuilder();
        int value;
        while ((value = reader.read()) != -1 && value != '\n') {
            if (text.length() >= 4096) throw new IllegalArgumentException("哈希行过长");
            text.append((char) value);
        }
        return value == -1 && text.isEmpty() ? null : text.toString();
    }
    public static Hash checkedHash(String sha, String name, int severity) {
        if (!sha.matches("[a-fA-F0-9]{64}") || name.isBlank() || name.length() > 255 || name.matches(".*\\s.*") || severity < 1 || severity > 5) throw new IllegalArgumentException("哈希情报格式非法");
        return new Hash(sha.toLowerCase(Locale.ROOT), name, severity);
    }
    public static void validateRule(JsonNode rule) {
        String name = rule.path("name").asText("");
        String platform = rule.path("platform").asText("all");
        String condition = rule.path("condition").asText("all");
        int severity = rule.path("severity").asInt(4);
        JsonNode strings = rule.path("strings");
        if (name.isBlank() || name.length() > 255 || !Set.of("all", "linux", "windows").contains(platform)
                || !Set.of("all", "any").contains(condition) || severity < 1 || severity > 5
                || !strings.isArray() || strings.isEmpty() || strings.size() > 128) throw new IllegalArgumentException("内部规则格式非法");
        for (JsonNode string : strings) {
            String type = string.path("type").asText("text"), value = string.path("value").asText("");
            if (!Set.of("text", "hex").contains(type) || value.isEmpty() || value.length() > 4096) throw new IllegalArgumentException("规则特征串非法");
            if ("hex".equals(type)) {
                String hex = value.replaceAll("\\s", "");
                if (hex.isEmpty() || hex.length() % 2 != 0 || !hex.matches("[A-Fa-f0-9]+")) throw new IllegalArgumentException("规则十六进制特征非法");
            }
        }
        if (!rule.path("name").isTextual() || (rule.has("platform") && !rule.path("platform").isTextual())
                || (rule.has("condition") && !rule.path("condition").isTextual())
                || (rule.has("severity") && !rule.path("severity").isIntegralNumber())
                || (rule.has("max_mb") && (!rule.path("max_mb").isIntegralNumber() || rule.path("max_mb").asInt() < 1 || rule.path("max_mb").asInt() > 50))) throw new IllegalArgumentException("规则字段类型非法");
        for (JsonNode string : strings) if (!string.path("value").isTextual() || (string.has("type") && !string.path("type").isTextual())) throw new IllegalArgumentException("规则特征串类型非法");
        if (rule.has("exts")) {
            if (!rule.path("exts").isArray()) throw new IllegalArgumentException("规则扩展名格式非法");
            for (JsonNode ext : rule.path("exts")) if (!ext.isTextual()) throw new IllegalArgumentException("规则扩展名类型非法");
        }
    }
    public static byte[] readBounded(InputStream input, long max) throws IOException {
        if (max < 0) throw new IllegalArgumentException("下载大小超过上限");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        long size = 0;
        while ((read = input.read(buffer)) != -1) {
            size += read;
            if (size > max) throw new IllegalArgumentException("下载或解压大小超过上限");
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }
    public static String sha256(Path path) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream input = Files.newInputStream(path)) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = input.read(buf)) != -1) digest.update(buf, 0, n);
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }
}
