package com.alinksec.service.geo;

import com.alinksec.common.util.JsonUtils;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.annotation.PreDestroy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.net.InetAddress;
import java.net.URI;
import java.net.URLEncoder;
import javax.net.ssl.HttpsURLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.function.LongSupplier;

/** Cached, bounded enrichment. A dashboard read never waits on the provider. */
@Service
public class GeoIpService implements AutoCloseable {
    interface Lookup { JsonNode query(String ip) throws Exception; }
    private record Entry(Map<String, Object> value, long expires) {}
    private final GeoIpProperties properties;
    private final Map<String, GeoLocationProvider> providers = new LinkedHashMap<>();
    private final Executor executor;
    private final LongSupplier clock;
    private final Map<String, Entry> cache = new LinkedHashMap<>();
    private long nextRequest, blockedUntil, generation;
    private static final int MAX_CACHE = 2048;

    @Autowired
    public GeoIpService(GeoIpProperties properties, List<GeoLocationProvider> providers) {
        this(properties, providers, new ThreadPoolExecutor(1, 1, 0, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(64), task -> { var t = new Thread(task, "geoip-lookup"); t.setDaemon(true); return t; },
                new ThreadPoolExecutor.AbortPolicy()), System::currentTimeMillis);
    }
    public GeoIpService(GeoIpProperties properties) { this(properties, List.of(new IpipGeoIpProvider(properties), new OfflineGeoIpProvider(properties))); }
    GeoIpService(GeoIpProperties properties, Lookup lookup, Executor executor, LongSupplier clock) {
        this(properties, List.of(new GeoLocationProvider() {
            public String id() { return "ipip"; }
            public String status() { return IpipGeoIpProvider.credentialsStatus(properties); }
            public boolean remote() { return true; }
            public Map<String, Object> locate(String ip) throws Exception { return parse(ip, lookup.query(ip), clock.getAsLong()); }
        }), executor, clock);
    }
    GeoIpService(GeoIpProperties properties, List<GeoLocationProvider> providers, Executor executor, LongSupplier clock) {
        this.properties = properties; providers.forEach(p -> this.providers.put(p.id(), p)); this.executor = executor; this.clock = clock;
    }
    static Lookup provider(GeoIpProperties p) {
        // Fixed HTTPS origin, redirects disabled, bounded body; the key never reaches the browser.
        return ip -> {
            Path file = Path.of(p.getTokenFile());
            if (!Files.isRegularFile(file) || Files.size(file) > 512) throw new IllegalStateException("token_unavailable");
            String token = Files.readString(file).trim();
            if (token.isBlank() || token.contains("\r") || token.contains("\n")) throw new IllegalStateException("token_invalid");
            var connection = (HttpsURLConnection) URI.create("https://ipapi.ipip.net/query/" + URLEncoder.encode(ip, StandardCharsets.UTF_8)).toURL().openConnection();
            connection.setInstanceFollowRedirects(false);
            connection.setConnectTimeout(2000); connection.setReadTimeout(2000); connection.setRequestProperty("Token", token);
            try {
                if (connection.getResponseCode() != 200) throw new IllegalStateException("provider_unavailable");
                try (var body = connection.getInputStream(); var bytes = new java.io.ByteArrayOutputStream()) {
                    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
                    byte[] chunk = new byte[2048]; int length;
                    while (true) {
                        long remaining = deadline - System.nanoTime();
                        if (remaining <= 0) throw new java.net.SocketTimeoutException();
                        connection.setReadTimeout((int) Math.max(1, TimeUnit.NANOSECONDS.toMillis(remaining)));
                        length = body.read(chunk);
                        if (length < 0) break;
                        if (bytes.size() + length > 16384) throw new IllegalStateException("response_too_large");
                        bytes.write(chunk, 0, length);
                    }
                    return JsonUtils.read(bytes.toString(StandardCharsets.UTF_8));
                }
            } finally { connection.disconnect(); }

        };
    }
    public String status() {
        var enabled = enabled();
        if (enabled.stream().anyMatch(p -> "configured".equals(p.status()))) return "configured";
        return enabled.isEmpty() ? "disabled" : enabled.getFirst().status();
    }
    private List<GeoLocationProvider> enabled() {
        return java.util.stream.Stream.of(properties.getProvider(), properties.getFallbackProvider()).distinct()
                .map(providers::get).filter(java.util.Objects::nonNull).toList();
    }
    public Map<String, Object> metadata() {
        return Map.of("primary", properties.getProvider(), "fallback", properties.getFallbackProvider(), "status", status(),
                "providers", enabled().stream().map(GeoLocationProvider::metadata).toList());
    }
    public synchronized Map<String, Object> reload() {
        var offline = providers.get("offline"); boolean loaded = offline != null && offline.reload();
        if (loaded) { generation++; cache.clear(); blockedUntil = 0; }
        return Map.of("reloaded", loaded, "info", metadata());
    }
    public synchronized Map<String, Object> locate(String raw) {
        String ip = literal(raw);
        if (ip == null) return state("invalid_ip");
        if (!publicAddress(ip)) return state("non_public_ip");
        if (!"configured".equals(status())) return state(status());
        long now = clock.getAsLong();
        Entry hit = cache.get(ip);
        if (hit != null && hit.expires > now) return hit.value;
        if (cache.size() >= MAX_CACHE) {
            var iterator = cache.entrySet().iterator(); iterator.next(); iterator.remove();
        }
        cache.put(ip, new Entry(state("pending"), now + 300000));
        long ticket = generation;
        try { executor.execute(() -> resolve(ip, ticket)); }
        catch (RejectedExecutionException e) { cache.put(ip, new Entry(state("busy"), now + 5000)); }
        return cache.get(ip).value;
    }
    private void resolve(String ip, long ticket) {
        Map<String, Object> value = state(status());
        for (var provider : enabled()) {
            if (!"configured".equals(provider.status())) continue;
            try {
                if (provider.remote()) {
                    long delay;
                    synchronized (this) {
                        if (clock.getAsLong() < blockedUntil) { value = state("rate_limited"); continue; }
                        delay = Math.min(2000, Math.max(0, nextRequest - clock.getAsLong()));
                        nextRequest = clock.getAsLong() + delay + 2000;
                    }
                    // Only commercial remote calls are paced. Offline lookups never sleep.
                    if (delay > 0) Thread.sleep(delay);
                }
                value = provider.locate(ip);
            } catch (Exception e) { value = state("lookup_failed"); }
            if ("located".equals(value.get("status"))) break;
            if (provider.remote()) synchronized (this) { blockedUntil = clock.getAsLong() + 60000; }
        }
        synchronized (this) {
            if (generation != ticket) return;
            boolean success = "located".equals(value.get("status"));
            cache.put(ip, new Entry(value, clock.getAsLong() + (success ? 86400000 : 300000)));
            while (cache.size() > MAX_CACHE) { var it = cache.entrySet().iterator(); it.next(); it.remove(); }
        }
    }
    static Map<String, Object> parse(String ip, JsonNode root, long now) {
        var data = root.path("data"); var location = data.path("location");
        if (!"ok".equals(root.path("ret").asText()) || !ip.equals(literal(data.path("ip").asText()))) return state("lookup_failed");
        Double lat = coordinate(location.path("latitude")), lon = coordinate(location.path("longitude"));
        if (!valid(lat, lon)) return state("coordinates_missing");
        return Map.of("status", "located", "provider", "ipip", "precision", "city_approximate", "ip", ip,
                "latitude", lat, "longitude", lon, "label", String.join(" ", location.path("country_name").asText(),
                        location.path("region_name").asText(), location.path("city_name").asText()).trim(), "lookedUpAt", now);
    }
    private static Double coordinate(JsonNode node) {
        if (!node.isNumber() && !node.isTextual()) return null;
        try { return Double.valueOf(node.asText()); } catch (Exception e) { return null; }
    }
    static boolean valid(Double lat, Double lon) { return lat != null && lon != null && Double.isFinite(lat) && Double.isFinite(lon) && Math.abs(lat) <= 90 && Math.abs(lon) <= 180; }
    public Map<String, Object> asset(String agentId, String ip) {
        var asset = properties.getAssets().get(agentId);
        if (asset != null && valid(asset.getLatitude(), asset.getLongitude())) return Map.of("status", "located", "provider", "asset_inventory",
                "precision", "asset_configured", "latitude", asset.getLatitude(), "longitude", asset.getLongitude(), "label", asset.getLabel());
        return locate(ip);
    }
    static Map<String, Object> state(String reason) { return Map.of("status", reason); }
    static String literal(String value) {
        if (value == null || value.length() > 45 || value.isBlank()) return null;
        try {
            if (value.contains(":")) {
                if (!value.matches("[0-9A-Fa-f:.]+")) return null;
            } else {
                String[] parts = value.split("\\.", -1); if (parts.length != 4) return null;
                for (String p : parts) if (!p.matches("0|[1-9][0-9]{0,2}") || Integer.parseInt(p) > 255) return null;
            }
            return InetAddress.getByName(value).getHostAddress(); // Strict literal grammar above prevents DNS.
        } catch (Exception e) { return null; }
    }
    static boolean publicAddress(String value) {
        try {
            var address = InetAddress.getByName(value); byte[] b = address.getAddress();
            if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress() || address.isSiteLocalAddress() || address.isMulticastAddress()) return false;
            if (b.length == 4) {
                int a = b[0] & 255, c = b[1] & 255, d = b[2] & 255;
                return a != 0 && a < 224 && !(a == 100 && c >= 64 && c <= 127) && !(a == 198 && (c == 18 || c == 19))
                        && !(a == 192 && c == 0 && (d == 0 || d == 2)) && !(a == 192 && c == 88 && d == 99)
                        && !(a == 198 && c == 51 && d == 100) && !(a == 203 && c == 0 && d == 113);
            }
            int first = b[0] & 255, second = b[1] & 255;
            return (first & 0xe0) == 0x20
                    && !(first == 0x20 && second == 1 && (b[2] & 255) <= 1)
                    && !(first == 0x20 && second == 1 && (b[2] & 255) == 0x0d && (b[3] & 255) == 0xb8)
                    && !(first == 0x20 && second == 2)
                    && !(first == 0x3f && second == 0xff && (b[2] & 0xf0) == 0);
        } catch (Exception e) { return false; }
    }
    @Override @PreDestroy public void close() { if (executor instanceof ExecutorService service) service.shutdownNow(); }
}
