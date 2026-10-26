package com.alinksec.service.geo;

import com.alinksec.common.util.JsonUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class OfflineGeoIpProviderTest {
    @TempDir Path temp;
    GeoIpProperties properties() throws Exception {
        var p = new GeoIpProperties(); p.setProvider("offline");
        p.setDatabaseFile(Path.of(getClass().getResource("/geoip/GeoIP2-City-Test.mmdb").toURI()).toString()); return p;
    }
    @Test void memoryMappedCityRecordsSupportIpv4Ipv6AndPreserveActiveReaderOnBadUpdate() throws Exception {
        var p = properties();
        try (var provider = new OfflineGeoIpProvider(p)) {
            assertEquals("configured", provider.status());
            var city = provider.locate("81.2.69.160");
            assertEquals("located", city.get("status")); assertEquals("maxmind", city.get("provider"));
            assertTrue(GeoIpService.valid((Double) city.get("latitude"), (Double) city.get("longitude")));
            assertEquals("located", provider.locate("2001:218::").get("status"));
            var broken = temp.resolve("broken.mmdb"); Files.write(broken, new byte[256]); p.setDatabaseFile(broken.toString());
            assertFalse(provider.reload()); assertEquals("configured", provider.status());
            assertEquals("database_invalid", provider.metadata().get("lastReload"));
            assertEquals(city.get("latitude"), provider.locate("81.2.69.160").get("latitude"));
            p.setDatabaseFile(temp.resolve("missing.mmdb").toString()); assertFalse(provider.reload());
            assertEquals("located", provider.locate("81.2.69.160").get("status"));
        }
    }
    @Test void offlinePrimaryUsesCommercialFallbackOnlyForMissingRecordsAndReloadClearsCache() throws Exception {
        var p = properties(); p.setFallbackProvider("ipip"); var calls = new AtomicInteger();
        GeoLocationProvider fallback = new GeoLocationProvider() {
            public String id() { return "ipip"; }
            public String status() { return "configured"; }
            public boolean remote() { return true; }
            public Map<String,Object> locate(String ip) { calls.incrementAndGet(); return GeoIpService.parse(ip, GeoIpServiceTest.response(ip), 1); }
        };
        try (var offline = new OfflineGeoIpProvider(p); var geo = new GeoIpService(p, List.of(offline, fallback), Runnable::run, System::currentTimeMillis)) {
            assertEquals("maxmind", geo.locate("81.2.69.160").get("provider")); assertEquals(0, calls.get());
            assertEquals("ipip", geo.locate("8.8.8.8").get("provider")); assertEquals(1, calls.get());
            assertEquals("ipip", geo.locate("8.8.8.8").get("provider")); assertEquals(1, calls.get());
            assertEquals(true, geo.reload().get("reloaded"));
            assertEquals("ipip", geo.locate("8.8.8.8").get("provider")); assertEquals(2, calls.get());
        }
    }
    @Test void locallyInstalledFullManufacturerDatabaseReturnsActualIpv4AndIpv6Coordinates() throws Exception {
        String file = System.getenv("ALINKSEC_GEOIP_ACCEPTANCE_DATABASE");
        assumeTrue(file != null, "full vendor database is installed separately for local acceptance");
        var p = properties(); p.setDatabaseFile(file);
        try (var offline = new OfflineGeoIpProvider(p)) {
            assertEquals("configured", offline.status());
            assertTrue(String.valueOf(offline.metadata().get("databaseType")).toLowerCase().contains("dbip"));
            for (String ip : List.of("8.8.8.8", "118.28.8.8", "2606:4700:4700::1111")) {
                var value = offline.locate(ip); assertEquals("located", value.get("status"), ip);
                assertEquals("dbip", value.get("provider"));
                assertTrue(GeoIpService.valid((Double)value.get("latitude"), (Double)value.get("longitude")));
            }
            assertEquals(6, offline.metadata().get("ipVersion"));
        }
    }
}
