package com.alinksec.service.baseline;

import com.alinksec.common.util.JsonUtils;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.re2j.Pattern;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.security.MessageDigest;
import java.util.*;

/** Validate a bounded, declarative package without running checks or fetching its source. */
public final class BaselinePackageFormat {
    public static final int MAX_BYTES = 2 * 1024 * 1024;
    private static final ObjectMapper STRICT = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private static final Map<String, Set<String>> COMMANDS;
    static {
        try (var stream = BaselinePackageFormat.class.getResourceAsStream("/baseline/commands.json")) {
            if (stream == null) throw new IOException("Missing compiled command registry");
            JsonNode registry = STRICT.readTree(stream);
            Map<String, Set<String>> platforms = new HashMap<>();
            registry.fields().forEachRemaining(entry -> {
                Set<String> values = new HashSet<>(); entry.getValue().forEach(value -> values.add(value.asText()));
                platforms.put(entry.getKey(), Set.copyOf(values));
            });
            COMMANDS = Map.copyOf(platforms);
        } catch (IOException e) { throw new ExceptionInInitializerError(e); }
    }
    public record Validated(JsonNode document, String sha256) {}
    private BaselinePackageFormat() {}

    public static Validated read(InputStream input) throws IOException {
        byte[] bytes = input.readNBytes(MAX_BYTES + 1);
        require(bytes.length <= MAX_BYTES, "模板包最多 2 MiB");
        JsonNode doc;
        try { doc = STRICT.readTree(bytes); }
        catch (IOException e) { throw new IllegalArgumentException("模板包 JSON 无效或包含重复字段"); }
        fields(doc, "schemaVersion", "code", "name", "standard", "product", "osType",
                "osVersionPattern", "version", "source", "items", "unsupported");
        require(doc.path("schemaVersion").isInt() && doc.path("schemaVersion").intValue() == 1, "模板包格式版本必须为 1");
        require(text(doc, "code", 40).matches("[A-Za-z0-9][A-Za-z0-9_.-]*"), "模板编号只能包含字母、数字、点、横线和下划线");
        text(doc, "name", 128); text(doc, "standard", 64); text(doc, "product", 128); text(doc, "version", 32);
        require(doc.path("osType").isInt(), "osType 必须为整数");
        int os = doc.path("osType").intValue();
        require(os == 1 || os == 2, "osType 只支持 Linux(1) 或 Windows(2)");
        String applicability = text(doc, "osVersionPattern", 512);
        require(applicability.startsWith("^") && applicability.endsWith("$"), "系统适用表达式必须以 ^ 开始、以 $ 结束");
        regex(applicability);
        JsonNode source = doc.path("source");
        fields(source, "name", "version", "url", "sha256");
        text(source, "name", 128); text(source, "version", 64);
        URI uri;
        try { uri = URI.create(text(source, "url", 1024)); }
        catch (RuntimeException e) { throw new IllegalArgumentException("来源链接无效"); }
        require("https".equals(uri.getScheme()) && uri.getHost() != null && uri.getUserInfo() == null
                && uri.getFragment() == null, "来源必须为不含凭据的 HTTPS 链接");
        require(text(source, "sha256", 64).matches("[a-f0-9]{64}"), "来源 SHA256 必须为 64 位小写十六进制");
        JsonNode items = doc.path("items"), unsupported = doc.path("unsupported");
        require(items.isArray() && items.size() > 0 && items.size() <= 500, "模板包需有 1 至 500 项可执行检查");
        require(unsupported.isArray() && items.size() + unsupported.size() <= 2000, "规则总数最多 2000，unsupported 必须为数组");
        Set<String> codes = new HashSet<>(), rules = new HashSet<>();
        for (JsonNode item : items) {
            fields(item, "code", "ruleId", "name", "category", "severity", "check", "remediation");
            String code = text(item, "code", 64);
            require(code.matches("[A-Za-z0-9][A-Za-z0-9_.-]*") && codes.add(code), "检查编号无效或重复: " + code);
            require(rules.add(text(item, "ruleId", 255)), "原始规则编号重复");
            text(item, "name", 255); text(item, "category", 64); optionalText(item, "remediation", 4000);
            require(item.path("severity").isInt() && item.path("severity").intValue() >= 1
                    && item.path("severity").intValue() <= 4, "检查严重度必须为 1 至 4");
            validateCheck(item.path("check"), os);
        }
        for (JsonNode item : unsupported) {
            fields(item, "ruleId", "reason");
            require(rules.add(text(item, "ruleId", 255)), "原始规则编号重复");
            text(item, "reason", 1000);
        }
        // Sorting object keys makes the content digest independent of whitespace and field order.
        JsonNode canonical = STRICT.valueToTree(canonical(doc));
        try {
            String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(JsonUtils.write(canonical).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            return new Validated(canonical, digest);
        } catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }

    public static void validateCheck(JsonNode check, int os) {
        String type = text(check, "type", 32);
        switch (type) {
            case "file_content" -> {
                fields(check, "type", "target", "regex", "timeout_ms");
                target(check, os); regex(text(check, "regex", 1000));
            }
            case "file_line" -> {
                fields(check, "type", "target", "operator", "expected", "timeout_ms");
                target(check, os);
                String operator = text(check, "operator", 32), expected = text(check, "expected", 1000);
                require(Set.of("regex", "contains", "not_contains").contains(operator), "file_line 运算符不支持");
                if (operator.equals("regex")) regex(expected);
            }
            case "file_perm" -> {
                fields(check, "type", "target", "perm", "owner", "group", "timeout_ms");
                require(os == 1, "Windows 不支持 file_perm"); target(check, os);
                String perm = optionalText(check, "perm", 4), owner = optionalText(check, "owner", 64), group = optionalText(check, "group", 64);
                require(!perm.isEmpty() || !owner.isEmpty() || !group.isEmpty(), "file_perm 需指定权限、属主或属组");
                require(perm.isEmpty() || perm.matches("[0-7]{4}"), "权限必须为四位八进制");
                require(owner.isEmpty() || owner.matches("[A-Za-z0-9_.-]+"), "属主无效");
                require(group.isEmpty() || group.matches("[A-Za-z0-9_.-]+"), "属组无效");
            }
            case "cmd_output" -> {
                fields(check, "type", "cmd", "operator", "expected", "timeout_ms");
                require(COMMANDS.get(os == 1 ? "linux" : "windows").contains(text(check, "cmd", 2048)), "命令未获目标平台 Agent 允许列表许可");
                String op = text(check, "operator", 32), expected = optionalText(check, "expected", 1000);
                require(check.has("expected"), "cmd_output 需指定 expected");
                require(Set.of("eq", "ne", "contains", "not_contains", "regex", "gt", "gte", "lt", "lte").contains(op), "cmd_output 运算符不支持");
                if (op.equals("regex")) regex(expected);
                if (Set.of("gt", "gte", "lt", "lte").contains(op)) {
                    try { require(Double.isFinite(Double.parseDouble(expected)), "期望值必须为有限数值"); }
                    catch (NumberFormatException e) { throw new IllegalArgumentException("期望值必须为有限数值"); }
                }
            }
            case "sshd_effective" -> {
                fields(check, "type", "target", "option", "connection", "operator", "expected", "timeout_ms");
                require(os == 1, "sshd_effective 当前仅支持 Linux OpenSSH"); target(check, os);
                require(Set.of("permitrootlogin", "maxauthtries").contains(text(check, "option", 32)), "SSH 配置项尚未支持");
                JsonNode connection = check.path("connection");
                fields(connection, "user", "host", "address", "local_address", "local_port");
                require(text(connection, "user", 64).matches("[A-Za-z_][A-Za-z0-9_.-]{0,63}"), "SSH 用户无效");
                require(!check.path("option").asText().equals("permitrootlogin") || connection.path("user").asText().equals("root"), "root 登录策略必须使用 root 连接条件");
                require(text(connection, "host", 253).matches("[A-Za-z0-9][A-Za-z0-9.-]{0,252}"), "SSH 来源主机无效");
                require(ipLiteral(text(connection, "address", 45)) && ipLiteral(text(connection, "local_address", 45)), "SSH 地址需为 IPv4 或 IPv6 字面值");
                require(connection.path("local_port").isInt() && connection.path("local_port").intValue() >= 1
                        && connection.path("local_port").intValue() <= 65535, "SSH 本地端口需为 1 至 65535");
                String op = text(check, "operator", 32), expected = text(check, "expected", 1000);
                require(Set.of("eq", "regex").contains(op), "SSH 检查仅支持 eq 或 regex");
                if (op.equals("regex")) regex(expected);
            }
            case "linux_audit" -> {
                fields(check, "type", "target", "option", "operator", "expected", "timeout_ms");
                require(os == 1, "内核审计检查仅支持 Linux");
                require(text(check, "target", 1024).equals("kernel") && text(check, "operator", 32).equals("eq"), "内核审计仅支持固定查询和明确参考");
                String option = text(check, "option", 32);
                require(Set.of("enabled", "identity_watches").contains(option), "内核审计检查项尚未支持");
                require(text(check, "expected", 1000).equals(option.equals("enabled") ? "enabled=1|2"
                        : "enabled=1|2,always_exit_all,passwd_shadow_group_gshadow=wa"), "内核审计参考不能隐式扩展");
            }
            case "auditd_config" -> {
                fields(check, "type", "target", "option", "operator", "expected", "timeout_ms");
                require(os == 1, "auditd 配置检查仅支持 Linux");
                require(text(check, "target", 1024).equals("/etc/audit/auditd.conf") && text(check, "operator", 32).equals("eq"), "auditd 检查需固定磁盘配置和明确参考");
                String expected = switch (text(check, "option", 32)) {
                    case "local_logging" -> "local_events=yes,write_logs=yes,log_format=raw|enriched";
                    case "keep_logs" -> "local_logging=1,max_log_file>=1,max_log_file_action=keep_logs";
                    case "log_file_metadata" -> "local_logging=1,regular,mode<=0640,uid=0,gid=declared_numeric_log_group";
                    default -> throw new IllegalArgumentException("auditd 配置检查项尚未支持");
                };
                require(text(check, "expected", 1000).equals(expected), "auditd 参考不能隐式扩展");
            }
            case "linux_log_metadata" -> {
                fields(check, "type", "target", "operator", "perm", "owner", "group", "timeout_ms");
                require(os == 1, "日志元数据检查仅支持 Linux");
                String path = text(check, "target", 1024);
                require(Set.of("/var/log/audit", "/var/log/btmp", "/var/log/wtmp").contains(path), "日志路径限定固定参考路径");
                String perm = path.equals("/var/log/audit") ? "0700" : path.equals("/var/log/btmp") ? "0660" : "0664";
                String group = path.equals("/var/log/audit") ? "0" : "utmp";
                require(text(check, "operator", 32).equals("subset") && text(check, "perm", 4).equals(perm), "日志权限上限不能隐式扩展");
                require(text(check, "owner", 64).equals("0") && text(check, "group", 64).equals(group), "日志数值属主及本地属组需明确");
            }
            case "systemd_service" -> {
                fields(check, "type", "target", "operator", "expected", "timeout_ms");
                require(os == 1, "systemd 服务检查仅支持 Linux");
                require(Set.of("auditd.service", "rsyslog.service").contains(text(check, "target", 1024)), "systemd 检查限定 auditd/rsyslog 系统服务");
                require(text(check, "operator", 32).equals("eq") && text(check, "expected", 1000).equals("loaded/active/running"), "systemd 运行参考不能隐式扩展");
            }
            case "pam_auth" -> {
                fields(check, "type", "target", "option", "operator", "expected", "timeout_ms");
                require(os == 1, "PAM 认证检查仅支持 Linux");
                require(text(check, "target", 1024).equals("/etc/pam.d/login"), "PAM 认证检查限定 login 服务");
                require(text(check, "option", 32).equals("faillock") && text(check, "operator", 32).equals("eq"), "PAM 认证检查项或运算符不支持");
                require(text(check, "expected", 1000).equals("deny=1..5,fail_interval>=900,unlock_time=900..86400,explicit_even_deny_root=1,root_unlock_time=900..86400"), "PAM 锁定参考要求不能隐式扩展");
            }
            case "pam_password" -> {
                fields(check, "type", "target", "option", "operator", "expected", "timeout_ms");
                require(os == 1, "PAM 口令检查仅支持 Linux");
                require(text(check, "target", 1024).equals("/etc/pam.d/passwd"), "PAM 检查限定 passwd 服务");
                String option = text(check, "option", 32), expected = text(check, "expected", 1000);
                require(Set.of("quality", "unix_hash").contains(option) && text(check, "operator", 32).equals("eq"), "PAM 口令检查项或运算符不支持");
                require(expected.equals(option.equals("quality")
                        ? "minlen>=12,minclass>=3,credits<=0,enforcing=1,enforce_for_root=1,use_authtok=1" : "yescrypt"), "PAM 口令参考要求不能隐式扩展");
            }
            case "local_identity_file" -> {
                fields(check, "type", "target", "perm", "owner", "group", "operator", "timeout_ms");
                require(os == 1, "本地身份文件检查仅支持 Linux");
                require(Set.of("/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow").contains(text(check, "target", 1024)), "身份文件路径必须为固定本地路径");
                require(text(check, "operator", 32).equals("subset"), "身份文件权限需使用 subset 上限比较");
                require(text(check, "perm", 4).matches("[0-7]{4}"), "权限上限需为四位八进制");
                require(text(check, "owner", 64).equals("0"), "身份文件属主需为数值 UID 0");
                require(Set.of("0", "shadow").contains(text(check, "group", 64)), "身份文件属组需明确为 GID 0 或本地 shadow 组");
            }
            case "local_accounts" -> {
                String option = text(check, "option", 32);
                if (option.equals("system_shells")) fields(check, "type", "target", "option", "operator", "expected", "uid_min", "uid_max", "timeout_ms");
                else fields(check, "type", "target", "option", "operator", "expected", "timeout_ms");
                require(os == 1, "本地账户检查仅支持 Linux");
                require(Set.of("empty_password", "uid0_accounts", "system_shells").contains(option), "本地账户检查项尚未支持");
                require(text(check, "target", 1024).equals(option.equals("empty_password") ? "/etc/shadow" : "/etc/passwd"), "本地账户检查路径不匹配");
                require(text(check, "operator", 32).equals("eq"), "本地账户检查仅支持 eq");
                require(text(check, "expected", 1000).equals(option.equals("uid0_accounts") ? "root" : "0"), "本地账户期望值不匹配");
                if (option.equals("system_shells")) {
                    JsonNode min = check.path("uid_min"), max = check.path("uid_max");
                    require(min.isIntegralNumber() && min.canConvertToLong() && max.isIntegralNumber() && max.canConvertToLong()
                            && min.longValue() >= 1 && min.longValue() <= max.longValue() && max.longValue() <= 4294967294L, "需明确有效的非 root UID 范围");
                }
            }
            default -> throw new IllegalArgumentException("不支持的检查类型: " + type);
        }
        if (check.has("timeout_ms")) require(check.get("timeout_ms").isInt()
                && check.get("timeout_ms").intValue() >= 100 && check.get("timeout_ms").intValue() <= 30000,
                "检查超时需为 100 至 30000 毫秒");
    }

    public static boolean applies(int os, String pattern, Map<String, Object> agent) {
        return os == ((Number) agent.get("os_type")).intValue()
                && (pattern == null || Pattern.compile(pattern).matcher(Objects.toString(agent.get("os_version"), "")).matches());
    }
    private static void target(JsonNode node, int os) {
        String value = text(node, "target", 1024);
        require(os == 1 ? value.startsWith("/") : value.matches("^[A-Za-z]:\\\\.*"), "检查路径必须为目标平台的绝对路径");
        require(!Arrays.asList(value.replace('\\', '/').split("/")).contains(".."), "检查路径不能包含上级目录");
    }
    private static boolean ipLiteral(String value) {
        if (value.matches("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) {
            for (String part : value.split("\\."))
                if (Integer.parseInt(part) > 255 || part.length() > 1 && part.startsWith("0")) return false;
            return true;
        }
        // Only hex/colon literals reach getByName: no DNS lookup or zone IDs.
        if (!value.contains(":") || !value.matches("[0-9A-Fa-f:]+")) return false;
        try { return java.net.InetAddress.getByName(value) instanceof java.net.Inet6Address; }
        catch (java.net.UnknownHostException e) { return false; }
    }
    private static void regex(String value) {
        // RE2/J and Go share the linear-time RE2 syntax, rather than Java backtracking syntax.
        try { Pattern.compile(value); }
        catch (RuntimeException e) { throw new IllegalArgumentException("表达式不受 Agent RE2 支持"); }
    }
    private static String text(JsonNode node, String key, int max) {
        require(node != null && node.path(key).isTextual(), "缺少文本字段: " + key);
        String value = node.path(key).textValue();
        require(!value.isBlank() && value.length() <= max && value.chars().noneMatch(c -> c < 32 && c != '\n' && c != '\t'), "文本字段无效或过长: " + key);
        return value;
    }
    private static String optionalText(JsonNode node, String key, int max) {
        if (!node.has(key)) return "";
        if (node.path(key).isTextual() && node.path(key).textValue().isEmpty()) return "";
        return text(node, key, max);
    }
    private static void fields(JsonNode node, String... allowed) {
        require(node != null && node.isObject(), "模板包字段必须为对象");
        Set<String> keys = Set.of(allowed);
        node.fieldNames().forEachRemaining(key -> require(keys.contains(key), "未知字段: " + key));
    }
    private static Object canonical(JsonNode node) {
        if (node.isObject()) {
            Map<String, Object> sorted = new TreeMap<>();
            node.fields().forEachRemaining(entry -> sorted.put(entry.getKey(), canonical(entry.getValue())));
            return sorted;
        }
        if (node.isArray()) { List<Object> values = new ArrayList<>(); node.forEach(value -> values.add(canonical(value))); return values; }
        return JsonUtils.mapper().convertValue(node, Object.class);
    }
    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalArgumentException(message);
    }
}
