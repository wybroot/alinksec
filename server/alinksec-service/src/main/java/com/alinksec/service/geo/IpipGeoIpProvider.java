package com.alinksec.service.geo;

import org.springframework.stereotype.Component;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

@Component
public class IpipGeoIpProvider implements GeoLocationProvider {
    private final GeoIpProperties properties;
    private final GeoIpService.Lookup lookup;
    public IpipGeoIpProvider(GeoIpProperties properties) { this.properties = properties; lookup = GeoIpService.provider(properties); }
    @Override public String id() { return "ipip"; }
    @Override public boolean remote() { return true; }
    @Override public String status() { return credentialsStatus(properties); }
    static String credentialsStatus(GeoIpProperties p) {
        try { return !p.getTokenFile().isBlank() && Files.isRegularFile(Path.of(p.getTokenFile()))
                && Files.size(Path.of(p.getTokenFile())) > 0 && Files.size(Path.of(p.getTokenFile())) <= 512 ? "configured" : "credentials_missing"; }
        catch (Exception e) { return "credentials_missing"; }
    }
    @Override public Map<String, Object> locate(String ip) throws Exception { return GeoIpService.parse(ip, lookup.query(ip), System.currentTimeMillis()); }
}
