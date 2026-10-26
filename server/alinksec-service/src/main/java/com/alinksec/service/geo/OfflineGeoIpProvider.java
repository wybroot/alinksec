package com.alinksec.service.geo;

import com.alinksec.common.util.JsonUtils;
import com.maxmind.db.Reader;
import jakarta.annotation.PreDestroy;
import org.springframework.stereotype.Component;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;

/** One memory-mapped reader: the full database is never copied into the Java heap. */
@Component
public class OfflineGeoIpProvider implements GeoLocationProvider, AutoCloseable {
    private final GeoIpProperties properties;
    private Reader reader;
    private String state = "database_missing", lastReload = "not_loaded";
    public OfflineGeoIpProvider(GeoIpProperties properties) { this.properties = properties; reload(); }
    @Override public String id() { return "offline"; }
    @Override public synchronized String status() { return reader == null ? state : "configured"; }
    @Override public synchronized boolean reload() {
        Reader candidate = null;
        try {
            Path file = Path.of(properties.getDatabaseFile());
            if (!Files.isRegularFile(file)) { state = "database_missing"; lastReload = state; return false; }
            if (Files.size(file) < 128 || Files.size(file) > 1L << 30) throw new IllegalArgumentException();
            candidate = new Reader(file.toFile(), Reader.FileMode.MEMORY_MAPPED);
            if (!candidate.getMetadata().databaseType().toLowerCase(java.util.Locale.ROOT).contains("city")) throw new IllegalArgumentException();
            long built = buildTime(candidate);
            if (built <= 0 || built > System.currentTimeMillis() + 86400000) throw new IllegalArgumentException();
            // Decode actual records before swapping so a damaged replacement cannot discard the active reader.
            candidate.get(InetAddress.getByName("8.8.8.8"), Map.class);
            if (candidate.getMetadata().ipVersion() == 6) candidate.get(InetAddress.getByName("2606:4700:4700::1111"), Map.class);
            Reader previous = reader; reader = candidate; candidate = null;
            state = "configured"; lastReload = "loaded";
            if (previous != null) previous.close();
            return true;
        } catch (Exception e) { state = "database_invalid"; lastReload = state; return false; }
        finally { if (candidate != null) try { candidate.close(); } catch (Exception ignored) {} }
    }
    @Override public synchronized Map<String, Object> metadata() {
        if (reader == null) return Map.of("id", id(), "status", status(), "lastReload", lastReload);
        var meta = reader.getMetadata();
        long built = buildTime(reader), days = Math.max(0, (System.currentTimeMillis() - built) / 86400000);
        return Map.of("id", id(), "status", status(), "databaseType", meta.databaseType(), "buildEpoch", built,
                "version", Instant.ofEpochMilli(built).toString(), "ageDays", days, "stale", days > 45,
                "ipVersion", meta.ipVersion(), "lastReload", lastReload);
    }
    @Override public synchronized Map<String, Object> locate(String ip) throws Exception {
        if (reader == null) return GeoIpService.state(status());
        var value = reader.get(InetAddress.getByName(ip), Map.class);
        if (value == null) return GeoIpService.state("not_found");
        var root = JsonUtils.mapper().valueToTree(value);
        var location = root.path("location");
        if (!location.path("latitude").isNumber() || !location.path("longitude").isNumber()) return GeoIpService.state("coordinates_missing");
        double lat = location.path("latitude").doubleValue(), lon = location.path("longitude").doubleValue();
        if (!GeoIpService.valid(lat, lon)) return GeoIpService.state("coordinates_missing");
        String vendor = reader.getMetadata().databaseType().toLowerCase(java.util.Locale.ROOT).contains("dbip") ? "dbip" : "maxmind";
        var labels = new java.util.LinkedHashSet<String>();
        for (var part : java.util.List.of(root.path("country"), root.path("subdivisions").path(0), root.path("city"))) {
            String label = part.path("names").path("zh-CN").asText(part.path("names").path("en").asText());
            if (!label.isBlank()) labels.add(label);
        }
        return Map.of("status", "located", "provider", vendor, "precision", "city_approximate", "ip", ip,
                "latitude", lat, "longitude", lon, "label", String.join(" ", labels),
                "databaseVersion", buildTime(reader), "lookedUpAt", System.currentTimeMillis());
    }
    private static long buildTime(Reader reader) { return Math.multiplyExact(reader.getMetadata().buildEpoch().longValueExact(), 1000); }
    @Override @PreDestroy public synchronized void close() { if (reader != null) try { reader.close(); } catch (Exception ignored) {} finally { reader = null; } }
}
