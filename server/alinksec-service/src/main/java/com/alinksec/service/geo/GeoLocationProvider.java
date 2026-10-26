package com.alinksec.service.geo;

import java.util.Map;

/** Vendor adapters return the same evidence fields; unavailable coordinates stay absent. */
public interface GeoLocationProvider {
    String id();
    String status();
    Map<String, Object> locate(String literalIp) throws Exception;
    default Map<String, Object> metadata() { return Map.of("id", id(), "status", status()); }
    default boolean remote() { return false; }
    default boolean reload() { return false; }
}
