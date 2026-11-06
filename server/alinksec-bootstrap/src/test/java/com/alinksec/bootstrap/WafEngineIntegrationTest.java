package com.alinksec.bootstrap;

import com.alinksec.service.waf.WafEngineService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.junit.jupiter.api.Assertions.*;

public class WafEngineIntegrationTest {

    private IntegrationTestFixture fixture;
    private JdbcTemplate jdbc;
    private WafEngineService wafService;

    @BeforeEach
    void setUp() {
        fixture = IntegrationTestFixture.create();
        jdbc = fixture.jdbc;
        wafService = fixture.context.getBean(WafEngineService.class);
    }

    @AfterEach
    void tearDown() {
        if (fixture != null) {
            fixture.close();
        }
    }

    @Test
    void testSqlInjectionDetectionAndBlocking() {
        // 1. DetectionOnly 模式：检测但阻断为 false
        wafService.updateConfig(true, "DetectionOnly", 5, 1);
        var result = wafService.inspect("GET", "/api/hosts", "id=1' UNION SELECT 1,username,password FROM t_user--",
                "Mozilla/5.0", "", "198.51.100.22");

        assertFalse(result.blocked(), "DetectionOnly 模式下不应阻断");
        assertTrue(result.anomalyScore() >= 5, "SQL 注入应获得足够异常评分");
        assertEquals("sql_injection", result.matchedCategory());

        // 2. 切换为 On (阻断模式)
        wafService.updateConfig(true, "On", 5, 1);
        var blockedResult = wafService.inspect("GET", "/api/hosts", "id=1' UNION SELECT 1,username,password FROM t_user--",
                "Mozilla/5.0", "", "198.51.100.22");

        assertTrue(blockedResult.blocked(), "On 模式下达到阈值必须阻断");
        assertEquals("sql_injection", blockedResult.matchedCategory());
    }

    @Test
    void testXssAndRceDetection() {
        wafService.updateConfig(true, "On", 5, 1);

        // XSS 尝试
        var xssResult = wafService.inspect("POST", "/api/comments", "", "Mozilla/5.0",
                "content=<script>alert('xss')</script>", "203.0.113.10");
        assertTrue(xssResult.blocked());
        assertEquals("xss", xssResult.matchedCategory());

        // RCE 尝试
        var rceResult = wafService.inspect("GET", "/api/tools/ping", "target=127.0.0.1;cat /etc/passwd",
                "Mozilla/5.0", "", "203.0.113.11");
        assertTrue(rceResult.blocked());
        assertEquals("rce", rceResult.matchedCategory());
    }

    @Test
    void testScannerDetectionByHeader() {
        wafService.updateConfig(true, "On", 5, 1);

        // sqlmap Scanner Header
        var scanResult = wafService.inspect("GET", "/api/test", "id=1", "sqlmap/1.6.0#stable (http://sqlmap.org)", "", "203.0.113.12");
        assertTrue(scanResult.blocked());
        assertEquals("scanner", scanResult.matchedCategory());
    }

    @Test
    void testExemptedInternalEndpointsAreNotBlocked() {
        wafService.updateConfig(true, "On", 5, 1);

        // 内部 API 上传升级包 / 特征库接口即使含有潜在关键词也应被豁免白名单保护
        var exemptResult = wafService.inspect("POST", "/api/upgrade/packages", "", "Mozilla/5.0",
                "payload=base64content", "127.0.0.1");
        assertFalse(exemptResult.blocked());
        assertEquals(0, exemptResult.anomalyScore());
    }

    @Test
    void testRequestBodyAndDoubleEncodingDetection() {
        wafService.updateConfig(true, "On", 5, 1);

        // R60: Body 中包含 SQL 注入
        var bodyResult = wafService.inspect("POST", "/api/login", "", "Mozilla/5.0",
                "{\"username\":\"admin' or 1=1-- \",\"password\":\"123456\"}", "198.51.100.33");
        assertTrue(bodyResult.blocked(), "Body 中的 SQL 注入必须被识别并阻断");
        assertEquals("sql_injection", bodyResult.matchedCategory());

        // R60: 双重 URL 编码绕过测试 (%252e%252e%252f -> %2e%2e%2f -> ../)
        var doubleEncodedResult = wafService.inspect("GET", "/api/files/download", "path=%252e%252e%252f%252e%252e%252fetc/passwd",
                "Mozilla/5.0", "", "198.51.100.34");
        assertTrue(doubleEncodedResult.blocked(), "双重 URL 编码的路径穿越必须被递归规范化后阻断");
        assertEquals("path_traversal", doubleEncodedResult.matchedCategory());
    }

    @Test
    void testCookieAndHeaderInspection() {
        wafService.updateConfig(true, "On", 5, 1);

        // Cookie 注入检测
        var cookieResult = wafService.inspect("GET", "/api/profile", "", "Mozilla/5.0", "", "198.51.100.40",
                java.util.Map.of(), java.util.Map.of("session_id", "admin' OR 1=1--"));
        assertTrue(cookieResult.blocked(), "Cookie 中的 SQL 注入必须被识别并阻断");
        assertEquals("sql_injection", cookieResult.matchedCategory());
        assertTrue(cookieResult.reason().contains("Cookie session_id"));

        // Header (Referer) 恶意注入
        var headerResult = wafService.inspect("GET", "/api/search", "q=test", "Mozilla/5.0", "", "198.51.100.41",
                java.util.Map.of("Referer", "http://evil.com/<script>alert(1)</script>"), java.util.Map.of());
        assertTrue(headerResult.blocked(), "Referer 中的 XSS 攻击必须被检测并阻断");
        assertEquals("xss", headerResult.matchedCategory());
        assertTrue(headerResult.reason().contains("Header Referer"));
    }

    @Test
    void testParanoiaLevels() {
        // PL1 模式下，PL2 盲注规则 (benchmark/sleep) 评分不足触发阻断 (阈值 5，PL1 规则不含 942200)
        wafService.updateConfig(true, "On", 5, 1);
        var pl1Result = wafService.inspect("GET", "/api/users", "name=test&delay=sleep(5)", "Mozilla/5.0", "", "198.51.100.42");
        // sleep 在 PL1 规则 942120 存在，但我们测试纯 PL2 规则如 benchmark(5000000) 或复杂组合
        var pl2OnlyResult = wafService.inspect("GET", "/api/users", "cmd=powershell.exe -enc AAAA", "Mozilla/5.0", "", "198.51.100.43");
        assertFalse(pl2OnlyResult.blocked(), "PL1 模式下不应触发 PL2 专属规则");

        // 提升至 PL2 模式，PL2 规则生效
        wafService.updateConfig(true, "On", 4, 2);
        var pl2ActiveResult = wafService.inspect("GET", "/api/users", "cmd=powershell.exe -enc AAAA", "Mozilla/5.0", "", "198.51.100.43");
        assertTrue(pl2ActiveResult.blocked(), "PL2 模式下必须触发 PL2 专属规则");
        assertEquals("rce", pl2ActiveResult.matchedCategory());
    }
}
