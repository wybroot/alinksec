package com.alinksec.service.geo;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.query.AlertQueryService;
import com.alinksec.service.alert.SecurityEventTaxonomy;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class GeoIpServiceTest {
    @TempDir Path temp;
    GeoIpProperties configured() throws Exception {
        var p = new GeoIpProperties(); p.setProvider("ipip");
        var file = temp.resolve("token"); Files.writeString(file, "test-only"); p.setTokenFile(file.toString()); return p;
    }
    static com.fasterxml.jackson.databind.JsonNode response(String ip) {
        return JsonUtils.read("{\"ret\":\"ok\",\"data\":{\"ip\":\""+ip+"\",\"location\":{\"latitude\":\"39.12\",\"longitude\":\"117.29\",\"city_name\":\"test\"}}}");
    }
    @Test void acceptsOnlyLiteralPublicAddressesWithoutDnsOrProviderCalls() throws Exception {
        var calls = new AtomicInteger(); var p = configured();
        var service = new GeoIpService(p, ip -> { calls.incrementAndGet(); return response(ip); }, Runnable::run, System::currentTimeMillis);
        for (String ip : List.of("localhost", "example.com", "127.1", "01.2.3.4", "1.2.3.999", "::1%lo")) assertEquals("invalid_ip", service.locate(ip).get("status"));
        for (String ip : List.of("127.0.0.1", "10.1.2.3", "172.31.1.1", "192.168.1.1", "100.64.0.1", "169.254.1.1", "203.0.113.1", "198.51.100.1", "192.0.2.1", "198.18.0.1", "0.1.2.3", "255.255.255.255", "::1", "fc00::1", "fe80::1", "2001:db8::1", "::ffff:127.0.0.1")) assertEquals("non_public_ip", service.locate(ip).get("status"), ip);
        assertEquals(0,calls.get()); assertTrue(GeoIpService.publicAddress(GeoIpService.literal("2606:4700:4700::1111")));
        for (String ip : List.of("2001:2::1", "2002:a00:1::1", "3fff::1", "192.88.99.1")) assertEquals("non_public_ip", service.locate(ip).get("status"));
    }
    @Test void snapshotIsNonBlockingSingleFlightAndCacheExpires() throws Exception {
        var queue = new ArrayList<Runnable>(); var now = new AtomicLong(100000); var calls = new AtomicInteger();
        var service = new GeoIpService(configured(), ip -> { calls.incrementAndGet(); return response(ip); }, queue::add, now::get);
        assertEquals("pending", service.locate("8.8.8.8").get("status"));
        assertEquals("pending", service.locate("8.8.8.8").get("status")); assertEquals(1,queue.size()); assertEquals(0,calls.get());
        queue.removeFirst().run(); assertEquals("located", service.locate("8.8.8.8").get("status")); assertEquals(1,calls.get());
        now.addAndGet(86400001); assertEquals("pending",service.locate("8.8.8.8").get("status")); assertEquals(1,queue.size());
    }
    @Test void missingCoordinatesMismatchedIpAndProviderErrorsNeverBecomeZeroCoordinates() {
        assertEquals("located", GeoIpService.parse("8.8.8.8",response("8.8.8.8"),1).get("status"));
        assertEquals("lookup_failed", GeoIpService.parse("8.8.4.4",response("8.8.8.8"),1).get("status"));
        for (String coordinates : List.of("{}", "{\"latitude\":null,\"longitude\":null}", "{\"latitude\":\"\",\"longitude\":\"\"}", "{\"latitude\":91,\"longitude\":0}", "{\"latitude\":\"NaN\",\"longitude\":0}")) {
            var value = GeoIpService.parse("8.8.8.8",JsonUtils.read("{\"ret\":\"ok\",\"data\":{\"ip\":\"8.8.8.8\",\"location\":"+coordinates+"}}"),1);
            assertEquals("coordinates_missing", value.get("status")); assertFalse(value.containsKey("latitude"));
        }
    }
    @Test void failureBackoffAndMissingConfigurationDoNotLeakCredentialsOrExceptions() throws Exception {
        var now = new AtomicLong(100000); var calls = new AtomicInteger();
        var service = new GeoIpService(configured(), ip -> { calls.incrementAndGet(); throw new IllegalStateException("secret-token-in-upstream-error"); }, Runnable::run, now::get);
        assertEquals(Map.of("status","lookup_failed"),service.locate("8.8.8.8"));
        assertEquals("rate_limited",service.locate("8.8.4.4").get("status")); assertEquals(1,calls.get());
        var p = new GeoIpProperties(); var disabled = new GeoIpService(p, ip -> fail("disabled provider called"), Runnable::run, now::get);
        assertEquals("disabled",disabled.locate("8.8.8.8").get("status")); p.setProvider("ipip"); assertEquals("credentials_missing",disabled.locate("8.8.8.8").get("status"));
    }
    @Test void privateTargetsRequireExplicitAssetCoordinatesAndLocalEventsHaveNoAttackSource() throws Exception {
        var p=configured(); var asset=new GeoIpProperties.Asset(); asset.setLatitude(0.0);asset.setLongitude(0.0);asset.setLabel("operator supplied"); p.getAssets().put("agent-a",asset);
        var geo=new GeoIpService(p, ip -> fail("private/local events must not query provider"), Runnable::run, System::currentTimeMillis);
        assertEquals("asset_inventory",geo.asset("agent-a","10.1.1.1").get("provider")); assertEquals("non_public_ip",geo.asset("other","10.1.1.1").get("status"));
        var alerts=mock(AlertQueryService.class);
        when(alerts.list(null,null,null,null,1,20)).thenReturn(Map.of("list",List.of(Map.of("id",1,"event_type","file_tamper","agent_id","agent-a","host_ip","10.1.1.1","detail","{\"source_ip\":\"8.8.8.8\"}"))));
        var snapshot=new ScreenSituationService(alerts,geo).snapshot();
        var row=(Map<?,?>)((List<?>)snapshot.get("events")).getFirst();
        var source=(Map<?,?>)row.get("source"); assertEquals("",source.get("ip")); assertEquals("no_network_source",((Map<?,?>)source.get("location")).get("status"));
    }
    @Test void sshAndWebAttackReportsUseObservedSourceAndMissingSourcesStayAttackEvents() {
        for (String type : List.of("login_crack", "ssh_bruteforce", "web_attack", "sql_injection", "xss", "rce", "ssrf", "path_traversal", "port_scan")) {
            assertTrue(SecurityEventTaxonomy.network(type), type);
            assertEquals("8.8.8.8", SecurityEventTaxonomy.sourceIp(type,JsonUtils.read("{\"source_ip\":\"8.8.8.8\"}")));
            assertEquals("",SecurityEventTaxonomy.sourceIp(type,JsonUtils.read("{\"request\":\"8.8.8.8\",\"headers\":{\"X-Forwarded-For\":\"8.8.8.8\"}}")));
        }
        assertEquals("", SecurityEventTaxonomy.sourceIp("virus",JsonUtils.read("{\"source_ip\":\"8.8.8.8\"}")));
    }
}
