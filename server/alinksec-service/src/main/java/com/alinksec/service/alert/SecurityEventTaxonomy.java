package com.alinksec.service.alert;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Map;

/** Remote attack reports must carry an observed source_ip, never an IP guessed from request text. */
public final class SecurityEventTaxonomy {
    private SecurityEventTaxonomy() {}
    public static final Map<String, String> NETWORK_TYPES = Map.ofEntries(
            Map.entry("login_crack", "登录暴力破解"), Map.entry("login_anomaly", "异常登录"),
            Map.entry("ssh_bruteforce", "SSH 暴力破解"), Map.entry("rdp_bruteforce", "RDP 暴力破解"),
            Map.entry("credential_stuffing", "撞库攻击"), Map.entry("web_attack", "Web 攻击"),
            Map.entry("waf_attack", "WAF 攻击告警"), Map.entry("sql_injection", "SQL 注入"),
            Map.entry("xss", "跨站脚本攻击"), Map.entry("path_traversal", "路径穿越"),
            Map.entry("command_injection", "命令注入"), Map.entry("file_inclusion", "文件包含"),
            Map.entry("webshell_attack", "WebShell 攻击"), Map.entry("ssrf", "服务端请求伪造"),
            Map.entry("rce", "远程代码执行"), Map.entry("port_scan", "端口扫描"), Map.entry("network_attack", "网络攻击"));
    public static boolean network(String type) { return NETWORK_TYPES.containsKey(type); }
    public static String sourceIp(String type, JsonNode detail) {
        return network(type) && detail.path("source_ip").isTextual() ? detail.path("source_ip").textValue() : "";
    }
}
