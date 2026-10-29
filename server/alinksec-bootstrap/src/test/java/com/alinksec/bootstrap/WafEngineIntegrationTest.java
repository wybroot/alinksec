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
}
