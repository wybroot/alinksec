package com.alinksec.service.waf;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.alert.SecurityEventService;
import com.alinksec.proto.RptSecurityEvent;
import com.alinksec.proto.Severity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * OWASP CRS (Core Rule Set) 兼容检测与防护引擎（E01 - E04）：
 * 1. 运行模式：DetectionOnly（仅检测记录并告警） vs On（拦截并返回 403 阻断）。
 * 2. Anomaly Scoring 模型：单条规则计算评分，综合异常分数达到阈值（默认 5）触发阻断/告警。
 * 3. 攻击规则覆盖：
 *    - REQUEST-942: SQL 注入 (UNION SELECT, stacked query, OR '1'='1', comment dash, sleep/benchmark)
 *    - REQUEST-941: XSS 跨站脚本 (<script>, javascript:, onerror=, SVG vector)
 *    - REQUEST-932: RCE 远程命令执行 (反引号、管道符、/bin/sh, curl | sh, ;cat /etc/passwd)
 *    - REQUEST-930: LFI / 路径穿越 (../, %2e%2e/, /etc/passwd, \win.ini)
 *    - REQUEST-913: 恶意扫描器识别 (sqlmap, nikto, dirbuster, nmap, masscan, nessus)
 * 4. 误报调优与豁免规则（E03）：针对 ALinkSec 自有 API 的 multipart/form-data、token、sha256 digest、base64 内容设定白名单豁免。
 * 5. 模式热切换与状态持久化（E04）：支持管理员无需重启动态切换模式与规则参数。
 */
@Service
public class WafEngineService {

    private static final Logger log = LoggerFactory.getLogger(WafEngineService.class);

    private final JdbcTemplate jdbc;
    private final SecurityEventService eventService;

    // 默认配置
    private volatile boolean enabled = true;
    private volatile String mode = "DetectionOnly"; // DetectionOnly or On
    private volatile int anomalyThreshold = 5;
    private volatile int paranoiaLevel = 1; // PL 1-4
    private volatile String crsVersion = "v4.1.0-crs-compat";

    // 规则条目
    public record CrsRule(int ruleId, String category, int pl, int severityScore, Pattern pattern, String description) {}

    private final List<CrsRule> rules = new ArrayList<>();
    private final Set<Integer> disabledRules = ConcurrentHashMap.newKeySet();

    public WafEngineService(JdbcTemplate jdbc, SecurityEventService eventService) {
        this.jdbc = jdbc;
        this.eventService = eventService;
        initDefaultRules();
        loadPersistedConfig();
    }

    private void initDefaultRules() {
        // REQUEST-913: 扫描器特征
        rules.add(new CrsRule(913100, "scanner", 1, 5,
                Pattern.compile("(sqlmap|nikto|dirbuster|gobuster|wpscan|nmap|masscan|zgrab)", Pattern.CASE_INSENSITIVE),
                "发现自动化安全漏洞扫描工具特征"));

        // REQUEST-942: SQL 注入
        rules.add(new CrsRule(942100, "sql_injection", 1, 5,
                Pattern.compile("(\\bunion\\b.{1,40}\\bselect\\b|\\bselect\\b.{1,40}\\bfrom\\b|\\binsert\\b.{1,40}\\binto\\b|\\bdrop\\b.{1,40}\\btable\\b)", Pattern.CASE_INSENSITIVE),
                "检测到典型 SQL 注入语法模式 (UNION/SELECT/DROP)"));
        rules.add(new CrsRule(942110, "sql_injection", 1, 5,
                Pattern.compile("('\\s*or\\s*['\"\\d]=\\s*['\"\\d]|(?:--|#|/\\*).*?(?:$|\\r|\\n)|/\\*.*\\*/)", Pattern.CASE_INSENSITIVE),
                "检测到 SQL 永真条件或注释闭合攻击 (OR 1=1 / Comment Truncation)"));
        rules.add(new CrsRule(942120, "sql_injection", 1, 5,
                Pattern.compile("(\\bwaitfor\\b\\s+\\bdelay\\b|\\bsleep\\s*\\(\\s*\\d+\\s*\\)|\\bbenchmark\\s*\\()", Pattern.CASE_INSENSITIVE),
                "检测到 SQL 时间盲注与延时执行特征 (WAITFOR/SLEEP/BENCHMARK)"));

        // REQUEST-941: XSS 跨站脚本
        rules.add(new CrsRule(941100, "xss", 1, 5,
                Pattern.compile("(<\\s*script\\b[^>]*>|javascript\\s*:|data\\s*:\\s*text/html)", Pattern.CASE_INSENSITIVE),
                "检测到显式脚本注入与伪协议 (script / javascript:)"));
        rules.add(new CrsRule(941110, "xss", 1, 4,
                Pattern.compile("(\\bon(?:error|load|click|mouseover|submit)\\s*=|<svg[^>]*\\bonload)", Pattern.CASE_INSENSITIVE),
                "检测到 HTML 事件属性内联执行 XSS 特征"));

        // REQUEST-932: RCE 远程命令执行
        rules.add(new CrsRule(932100, "rce", 1, 5,
                Pattern.compile("([;|`&$\\(\\)]{1,2}\\s*(?:cat|ls|whoami|id|nc|bash|sh|curl|wget|powershell)\\b)", Pattern.CASE_INSENSITIVE),
                "检测到 Shell 元字符命令拼接与系统探测 (Command Chaining)"));
        rules.add(new CrsRule(932110, "rce", 1, 5,
                Pattern.compile("(\\b(?:curl|wget)\\b[^\\n]+\\|\\s*(?:sh|bash)\\b)", Pattern.CASE_INSENSITIVE),
                "检测到远程脚本管道直接执行特征 (curl | sh)"));

        // REQUEST-930: LFI 路径穿越
        rules.add(new CrsRule(930100, "path_traversal", 1, 5,
                Pattern.compile("(\\.\\./|\\.\\.\\\\|%2e%2e%2f|%2e%2e/)", Pattern.CASE_INSENSITIVE),
                "检测到目录向上遍历与路径穿越特征 (Directory Traversal)"));
        rules.add(new CrsRule(930110, "path_traversal", 1, 5,
                Pattern.compile("(/etc/(?:passwd|shadow|hosts|sudoers)|c:[\\\\/]windows[\\\\/]win\\.ini)", Pattern.CASE_INSENSITIVE),
                "检测到系统敏感凭据文件读取特征"));

        // === Paranoia Level 2 (PL 2) 规则 ===
        // REQUEST-942 (SQLi PL2): 盲注函数与高级关键字探测
        rules.add(new CrsRule(942200, "sql_injection", 2, 4,
                Pattern.compile("(\\b(?:benchmark|sleep|pg_sleep|char|hex|unhex|load_file|extractvalue|updatexml)\\s*\\()", Pattern.CASE_INSENSITIVE),
                "检测到高级 SQL 盲注与内建函数执行特征 (PL2)"));
        // REQUEST-941 (XSS PL2): 危险 HTML 标签与无引号事件处理器
        rules.add(new CrsRule(941200, "xss", 2, 4,
                Pattern.compile("(<\\s*(?:iframe|object|embed|applet|meta|link|style|base)\\b|\\bon[a-z]{3,15}\\s*=\\s*[^\"'\\s>]+)", Pattern.CASE_INSENSITIVE),
                "检测到高危内嵌标签与无引号事件处理器 (PL2)"));
        // REQUEST-932 (RCE PL2): 编码命令与 Windows 执行特征
        rules.add(new CrsRule(932200, "rce", 2, 4,
                Pattern.compile("(\\bpowershell(?:\\.exe)?\\s+.*-(?:enc|encodedcommand|command|ec)\\b|\\bcmd(?:\\.exe)?\\s+/c\\b|/dev/tcp/\\d)", Pattern.CASE_INSENSITIVE),
                "检测到高危命令解释器参数与反弹 Shell 管道 (PL2)"));
        // REQUEST-930 (Path Traversal PL2): 双重与复合路径穿越
        rules.add(new CrsRule(930200, "path_traversal", 2, 4,
                Pattern.compile("(?:\\.\\.[\\\\/]{1,2}){2,}|%252e%252e|%c0%ae%c0%ae", Pattern.CASE_INSENSITIVE),
                "检测到深层或多重编码目录穿越攻击 (PL2)"));

        // === Paranoia Level 3 (PL 3) 规则 ===
        // REQUEST-942 (SQLi PL3): 特殊系统变量与内联注释
        rules.add(new CrsRule(942300, "sql_injection", 3, 3,
                Pattern.compile("(/\\*!\\d+.*?\\*/|@@(?:version|datadir)|\\b(?:user|version|database|schema)\\s*\\(\\s*\\))", Pattern.CASE_INSENSITIVE),
                "检测到数据库内联注释注入与元数据探测 (PL3)"));
        // REQUEST-941 (XSS PL3): 动态样式与非标脚本属性
        rules.add(new CrsRule(941300, "xss", 3, 3,
                Pattern.compile("(\\bexpression\\s*\\(|vbscript:|behavior\\s*:|-moz-binding)", Pattern.CASE_INSENSITIVE),
                "检测到特定浏览器动态样式表达式执行 (PL3)"));
        // REQUEST-920 (Protocol PL3): 空字节截断攻击
        rules.add(new CrsRule(920100, "protocol_violation", 3, 4,
                Pattern.compile("(?:%00|\\\\x00|\\x00)", Pattern.CASE_INSENSITIVE),
                "检测到空字节注入与文件名截断攻击 (PL3)"));

        // === Paranoia Level 4 (PL 4) 规则 ===
        // REQUEST-942 (SQLi PL4): 非闭合单双引号与重音符号探测
        rules.add(new CrsRule(942400, "sql_injection", 4, 2,
                Pattern.compile("([\"'`][^\"'`]*?(?:--|#|/\\*)|['\"][\\s]*[=><])", Pattern.CASE_INSENSITIVE),
                "检测到严格模式下单引号探测与语法异常 (PL4)"));
        // REQUEST-932 (RCE PL4): Unix 特殊环境变量混淆
        rules.add(new CrsRule(932400, "rce", 4, 3,
                Pattern.compile("(\\$(?:\\{IFS\\}|IFS)|\\$\\{[a-zA-Z_][a-zA-Z0-9_]*\\})", Pattern.CASE_INSENSITIVE),
                "检测到 Shell 环境变量替换与字符规避特征 (PL4)"));
    }

    private void loadPersistedConfig() {
        try {
            var rows = jdbc.queryForList("SELECT property_key, property_value FROM t_system_config WHERE property_key LIKE 'waf.%'");
            for (var r : rows) {
                String k = (String) r.get("property_key");
                String v = (String) r.get("property_value");
                if ("waf.enabled".equals(k)) enabled = Boolean.parseBoolean(v);
                if ("waf.mode".equals(k) && Set.of("DetectionOnly", "On").contains(v)) mode = v;
                if ("waf.threshold".equals(k)) anomalyThreshold = Integer.parseInt(v);
                if ("waf.pl".equals(k)) paranoiaLevel = Integer.parseInt(v);
                if ("waf.crs_version".equals(k)) crsVersion = v;
            }
        } catch (Exception ignored) {
            // 在未执行迁移前容错
        }
    }

    public record InspectionResult(boolean blocked, int anomalyScore, String matchedCategory, String matchedRule, String reason) {}

    /**
     * 核心检测入口：检查 HTTP 请求要素（URI、参数、Header、Body 摘要）
     */
    public InspectionResult inspect(String method, String uri, String query, String userAgent, String bodySnippet, String clientIp) {
        return inspect(method, uri, query, userAgent, bodySnippet, clientIp, Collections.emptyMap(), Collections.emptyMap());
    }

    /**
     * 核心检测入口（支持 Header 与 Cookie 深度检测）
     */
    public InspectionResult inspect(String method, String uri, String query, String userAgent, String bodySnippet, String clientIp,
                                   Map<String, String> headers, Map<String, String> cookies) {
        if (!enabled) {
            return new InspectionResult(false, 0, "", "", "WAF disabled");
        }

        // E03: 针对 ALinkSec 内部 API 进行路径与参数豁免白名单检查
        if (isExemptedEndpoint(uri, method)) {
            return new InspectionResult(false, 0, "", "", "exempted_path");
        }

        int score = 0;
        String triggeredCategory = "";
        String triggeredRule = "";
        String reason = "";
        boolean bodyTruncated = bodySnippet != null && bodySnippet.length() >= 16384;

        // 解码与待检文本组装
        String decodedQuery = safeDecode(query);
        String decodedUri = safeDecode(uri);
        String decodedBody = safeDecode(bodySnippet);

        // 1. Scanner Header 检查
        if (userAgent != null && !userAgent.isBlank()) {
            for (CrsRule r : rules) {
                if ("scanner".equals(r.category) && !disabledRules.contains(r.ruleId)) {
                    if (r.pattern.matcher(userAgent).find()) {
                        score += r.severityScore;
                        triggeredCategory = "scanner";
                        triggeredRule = "CRS-" + r.ruleId;
                        reason = r.description + " [UA: " + userAgent + "]";
                        break;
                    }
                }
            }
        }

        // 2. URI, Query 与 Body 规则评估
        String inspectionText = decodedUri + " ? " + decodedQuery + " " + decodedBody;
        for (CrsRule r : rules) {
            if ("scanner".equals(r.category) || disabledRules.contains(r.ruleId) || r.pl > paranoiaLevel) {
                continue;
            }
            Matcher m = r.pattern.matcher(inspectionText);
            if (m.find()) {
                score += r.severityScore;
                if (triggeredCategory.isEmpty()) {
                    triggeredCategory = r.category;
                    triggeredRule = "CRS-" + r.ruleId;
                    reason = r.description + " [匹配: " + m.group() + "]";
                }
            }
        }

        // 3. Cookie 规则评估
        if (cookies != null && !cookies.isEmpty()) {
            for (var entry : cookies.entrySet()) {
                String cName = entry.getKey();
                String cVal = safeDecode(entry.getValue());
                String cookieText = cName + "=" + cVal;
                for (CrsRule r : rules) {
                    if ("scanner".equals(r.category) || disabledRules.contains(r.ruleId) || r.pl > paranoiaLevel) {
                        continue;
                    }
                    Matcher m = r.pattern.matcher(cookieText);
                    if (m.find()) {
                        score += r.severityScore;
                        if (triggeredCategory.isEmpty()) {
                            triggeredCategory = r.category;
                            triggeredRule = "CRS-" + r.ruleId;
                            reason = r.description + " [Cookie " + cName + " 匹配: " + m.group() + "]";
                        }
                    }
                }
            }
        }

        // 4. Header 深度规则评估
        if (headers != null && !headers.isEmpty()) {
            for (var entry : headers.entrySet()) {
                String hName = entry.getKey();
                String hVal = safeDecode(entry.getValue());
                for (CrsRule r : rules) {
                    if ("scanner".equals(r.category) || disabledRules.contains(r.ruleId) || r.pl > paranoiaLevel) {
                        continue;
                    }
                    Matcher m = r.pattern.matcher(hVal);
                    if (m.find()) {
                        score += r.severityScore;
                        if (triggeredCategory.isEmpty()) {
                            triggeredCategory = r.category;
                            triggeredRule = "CRS-" + r.ruleId;
                            reason = r.description + " [Header " + hName + " 匹配: " + m.group() + "]";
                        }
                    }
                }
            }
        }

        boolean shouldBlock = "On".equalsIgnoreCase(mode) && (score >= anomalyThreshold);

        // 只要产生评分（命中规则），即上报平台安全告警（E01）
        if (score > 0 && !triggeredCategory.isEmpty()) {
            reportWafAlert(clientIp, uri, method, triggeredCategory, triggeredRule, score, reason, shouldBlock ? "blocked" : "detected", bodyTruncated);
        }

        return new InspectionResult(shouldBlock, score, triggeredCategory, triggeredRule, reason);
    }

    private void reportWafAlert(String clientIp, String uri, String method, String category, String ruleId, int score, String reason, String action, boolean bodyTruncated) {
        try {
            Map<String, Object> detail = new LinkedHashMap<>();
            detail.put("source_ip", clientIp != null ? clientIp : "127.0.0.1");
            detail.put("request_uri", uri);
            detail.put("method", method);
            detail.put("category", category);
            detail.put("rule_id", ruleId);
            detail.put("anomaly_score", score);
            detail.put("threshold", anomalyThreshold);
            detail.put("mode", mode);
            detail.put("reason", reason);
            detail.put("crs_version", crsVersion);
            if (bodyTruncated) {
                detail.put("body_truncated", true);
            }
            RptSecurityEvent event = RptSecurityEvent.newBuilder()
                    .setRuleId(ruleId)
                    .setRuleName("OWASP CRS " + category + " 检出")
                    .setType("web_attack")
                    .setSeverity(score >= 5 ? Severity.SEV_HIGH : Severity.SEV_MEDIUM)
                    .setActionTaken(action)
                    .setDetail(JsonUtils.write(detail))
                    .setEventTs(System.currentTimeMillis())
                    .build();

            // 作为平台网关或本机的虚拟 Agent 告警上报
            eventService.onEvent("agent-gateway-waf", event);
        } catch (Exception ex) {
            log.warn("WAF 告警上报异常: {}", ex.getMessage());
        }
    }

    /**
     * E03 误报调优：ALinkSec 专用合法 API 路径与参数豁免
     */
    private boolean isExemptedEndpoint(String uri, String method) {
        if (uri == null) return false;
        // 豁免 1: 特征库 / 升级包分片上传与下载
        if (uri.startsWith("/api/upgrade/packages") || uri.startsWith("/api/libraries/upload") || uri.startsWith("/api/evidence/")) {
            return true;
        }
        // 豁免 2: 告警导出、日志搜索复杂语法
        if (uri.startsWith("/api/logs/search") || uri.startsWith("/api/reports/snapshots")) {
            return true;
        }
        // 豁免 3: 静态资源
        if (uri.startsWith("/assets/") || uri.endsWith(".js") || uri.endsWith(".css") || uri.endsWith(".svg") || uri.endsWith(".png")) {
            return true;
        }
        return false;
    }

    private String safeDecode(String input) {
        if (input == null || input.isBlank()) return "";
        String current = input;
        // R60: 多重 URL 编码递归解包规范化 (最多 3 轮防止畸形死循环)
        for (int i = 0; i < 3; i++) {
            if (!current.contains("%")) break;
            try {
                String decoded = URLDecoder.decode(current, StandardCharsets.UTF_8);
                if (decoded.equals(current)) break;
                current = decoded;
            } catch (Exception e) {
                break;
            }
        }
        return current;
    }

    /* ==================== 管理接口与配置热切换 (E02, E04) ==================== */

    public Map<String, Object> getStatus() {
        return Map.of(
                "enabled", enabled,
                "mode", mode,
                "anomalyThreshold", anomalyThreshold,
                "paranoiaLevel", paranoiaLevel,
                "crsVersion", crsVersion,
                "activeRuleCount", rules.size() - disabledRules.size(),
                "totalRuleCount", rules.size()
        );
    }

    public synchronized void updateConfig(boolean enabled, String mode, int threshold, int pl) {
        if (!Set.of("DetectionOnly", "On").contains(mode)) {
            throw new IllegalArgumentException("模式仅支持 DetectionOnly 或 On");
        }
        if (threshold < 1 || threshold > 50) {
            throw new IllegalArgumentException("阈值范围 1-50");
        }
        if (pl < 1 || pl > 4) {
            throw new IllegalArgumentException("偏执级别范围 1-4");
        }
        this.enabled = enabled;
        this.mode = mode;
        this.anomalyThreshold = threshold;
        this.paranoiaLevel = pl;

        // 持久化到 t_system_config
        persistConfig("waf.enabled", String.valueOf(enabled));
        persistConfig("waf.mode", mode);
        persistConfig("waf.threshold", String.valueOf(threshold));
        persistConfig("waf.pl", String.valueOf(pl));
        log.info("WAF 配置热更新生效: enabled={} mode={} threshold={} pl={}", enabled, mode, threshold, pl);
    }

    private void persistConfig(String key, String val) {
        try {
            jdbc.update("""
                INSERT INTO t_system_config (property_key, property_value) VALUES (?, ?)
                ON CONFLICT(property_key) DO UPDATE SET property_value = excluded.property_value
                """, key, val);
        } catch (Exception ignored) {}
    }
}
