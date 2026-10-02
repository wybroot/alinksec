package com.alinksec.service.protect;

import com.alinksec.common.util.JsonUtils;
import com.fasterxml.jackson.databind.JsonNode;

import java.net.InetAddress;
import java.time.ZoneId;
import java.util.Set;

final class ProtectionPolicyValidator {
    private ProtectionPolicyValidator() {}

    static void validate(String type, Object match, Object actions) {
        if (!Set.of("file_integrity", "login").contains(type)) return;
        JsonNode config = JsonUtils.read(JsonUtils.write(match));
        JsonNode response = JsonUtils.read(JsonUtils.write(actions));
        require(config.isObject(), "match 必须为对象");
        require(response.isArray() && !response.isEmpty() && response.size() <= 2, "actions 必须为非空数组且不能超过上限");
        Set<String> allowed = type.equals("login") ? Set.of("alert", "block_ip") : Set.of("alert", "restore");
        for (JsonNode action : response) require(action.isTextual() && allowed.contains(action.asText()), "不支持的防护动作");
        for (String platform : strings(config, "platforms", 2)) require(Set.of("linux", "windows").contains(platform), "不支持的平台");
        if (type.equals("file_integrity")) {
            var paths = strings(config, "paths", 64);
            require(!paths.isEmpty(), "至少需要一个受保护文件");
            for (String path : paths) {
                require(path.length() <= 4096 && path.indexOf('\0') < 0
                        && (path.startsWith("/") || path.matches("^[A-Za-z]:[\\\\/].+")), "受保护文件必须使用绝对路径");
            }
            integer(config, "max_file_bytes", 1, 1048576, 1048576);
            return;
        }
        integer(config, "window_sec", 1, 3600, 300);
        integer(config, "failure_threshold", 2, 100, 5);
        integer(config, "cooldown_sec", 1, 86400, 300);
        integer(config, "block_duration_sec", 5, 3600, 600);
        integer(config, "allowed_start_hour", 0, 23, 0);
        integer(config, "allowed_end_hour", 0, 24, 0);
        if (config.has("off_hours_enabled")) require(config.get("off_hours_enabled").isBoolean(), "异常时段开关必须为布尔值");
        if (config.has("ssh_ports")) {
            JsonNode ports = config.get("ssh_ports");
            require(ports.isArray() && ports.size() > 0 && ports.size() <= 16, "SSH 端口数量无效");
            for (JsonNode port : ports) require(port.isIntegralNumber() && port.canConvertToInt() && port.asInt() >= 1 && port.asInt() <= 65535, "SSH 端口无效");
        }
        for (String value : strings(config, "trusted_ips", 128)) require(validNetwork(value), "信任 IP 或网段无效");
        for (String user : strings(config, "user_exclude", 64)) require(user.length() <= 128 && user.indexOf('\0') < 0, "排除账户无效");
        if (config.has("timezone")) require(config.get("timezone").isTextual(), "时区必须为字符串");
        String zone = config.has("timezone") ? config.get("timezone").asText("") : "Local";
        require(!zone.isBlank(), "时区无效");
        if (!zone.equals("Local")) {
            require(ZoneId.getAvailableZoneIds().contains(zone), "时区必须为 IANA 名称或 UTC");
        }
    }

    private static int integer(JsonNode config, String key, int min, int max, int fallback) {
        if (!config.has(key)) return fallback;
        JsonNode value = config.get(key);
        require(value.isIntegralNumber() && value.canConvertToInt() && value.asInt() >= min && value.asInt() <= max, key + " 超出允许范围");
        return value.asInt();
    }

    private static java.util.List<String> strings(JsonNode config, String key, int max) {
        JsonNode values = config.get(key);
        if (values == null) return java.util.List.of();
        require(values.isArray() && values.size() <= max, key + " 必须为数组且不能超过上限");
        var result = new java.util.ArrayList<String>();
        for (JsonNode value : values) {
            require(value.isTextual() && !value.asText().isBlank(), key + " 不能包含空值");
            result.add(value.asText());
        }
        return result;
    }

    private static boolean validNetwork(String value) {
        String[] parts = value.split("/", -1);
        if (parts.length > 2 || !parts[0].matches("[0-9a-fA-F:.]+")) return false;
        try {
            if (!parts[0].contains(":")) {
                String[] octets = parts[0].split("\\.", -1);
                if (octets.length != 4) return false;
                for (String octet : octets) if (!octet.matches("[0-9]+") || Integer.parseInt(octet) > 255 || (octet.length() > 1 && octet.startsWith("0"))) return false;
            }
            InetAddress.getByName(parts[0]);
            int bits = parts[0].contains(":") ? 128 : 32;
            return parts.length == 1 || (parts[1].matches("[0-9]+") && Integer.parseInt(parts[1]) <= bits);
        } catch (Exception e) { return false; }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalArgumentException(message);
    }
}
