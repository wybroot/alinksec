package com.alinksec.service.geo;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import java.util.LinkedHashMap;
import java.util.Map;

@Component
@ConfigurationProperties(prefix = "alinksec.geoip")
public class GeoIpProperties {
    private String provider = "disabled";
    private String tokenFile = "";
    private String databaseFile = "./data/geoip.mmdb";
    private String fallbackProvider = "disabled";
    private Map<String, Asset> assets = new LinkedHashMap<>();
    public String getProvider() { return provider; }
    public void setProvider(String value) { provider = value; }
    public String getTokenFile() { return tokenFile; }
    public void setTokenFile(String value) { tokenFile = value; }
    public String getDatabaseFile() { return databaseFile; }
    public void setDatabaseFile(String value) { databaseFile = value; }
    public String getFallbackProvider() { return fallbackProvider; }
    public void setFallbackProvider(String value) { fallbackProvider = value; }
    public Map<String, Asset> getAssets() { return assets; }
    public void setAssets(Map<String, Asset> value) { assets = value; }
    public static class Asset {
        private Double latitude, longitude;
        private String label = "";
        public Double getLatitude() { return latitude; }
        public void setLatitude(Double value) { latitude = value; }
        public Double getLongitude() { return longitude; }
        public void setLongitude(Double value) { longitude = value; }
        public String getLabel() { return label; }
        public void setLabel(String value) { label = value; }
    }
}
