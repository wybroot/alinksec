package com.alinksec.service.library;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import java.util.ArrayList;
import java.util.List;

/** All remote access is explicitly configured by the deployment administrator. */
@Component
@ConfigurationProperties(prefix = "alinksec.libraries")
public class LibraryProperties {
    private String workDir = "./data/libraries";
    private long maxDownloadBytes = 64L << 20;
    private int maxHashes = 250_000;
    private int maxCvesPerImport = 10_000;
    private int retainVersions = 10;
    private int retainDays = 7;
    private Storage storage = new Storage();
    private List<Source> sources = new ArrayList<>();
    public String getWorkDir() { return workDir; }
    public void setWorkDir(String value) { workDir = value; }
    public long getMaxDownloadBytes() { return maxDownloadBytes; }
    public void setMaxDownloadBytes(long value) { maxDownloadBytes = value; }
    public int getMaxHashes() { return maxHashes; }
    public void setMaxHashes(int value) { maxHashes = value; }
    public int getMaxCvesPerImport() { return maxCvesPerImport; }
    public void setMaxCvesPerImport(int value) { maxCvesPerImport = value; }
    public int getRetainVersions() { return retainVersions; }
    public void setRetainVersions(int value) { retainVersions = value; }
    public int getRetainDays() { return retainDays; }
    public void setRetainDays(int value) { retainDays = value; }
    public Storage getStorage() { return storage; }
    public List<Source> getSources() { return sources; }
    public void setSources(List<Source> value) { sources = value; }

    public static class Storage {
        private String backend = "local", endpoint = "", bucket = "", region = "us-east-1";
        private String accessKey = "", secretKey = "", prefix = "alinksec";
        public String getBackend() { return backend; }
        public void setBackend(String v) { backend = v; }
        public String getEndpoint() { return endpoint; }
        public void setEndpoint(String v) { endpoint = v; }
        public String getBucket() { return bucket; }
        public void setBucket(String v) { bucket = v; }
        public String getRegion() { return region; }
        public void setRegion(String v) { region = v; }
        public String getAccessKey() { return accessKey; }
        public void setAccessKey(String v) { accessKey = v; }
        public String getSecretKey() { return secretKey; }
        public void setSecretKey(String v) { secretKey = v; }
        public String getPrefix() { return prefix; }
        public void setPrefix(String v) { prefix = v; }
    }

    public static class Source {
        private String id = "", type = "hashes", url = "", apiKey = "", mispTag = "";
        private boolean enabled;
        private long intervalMs = 3_600_000;
        private int initialDays = 7;
        private List<Product> products = new ArrayList<>();
        public String getId() { return id; }
        public void setId(String v) { id = v; }
        public String getType() { return type; }
        public void setType(String v) { type = v; }
        public String getUrl() { return url; }
        public void setUrl(String v) { url = v; }
        public String getApiKey() { return apiKey; }
        public void setApiKey(String v) { apiKey = v; }
        public String getMispTag() { return mispTag; }
        public void setMispTag(String v) { mispTag = v; }
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean v) { enabled = v; }
        public long getIntervalMs() { return intervalMs; }
        public void setIntervalMs(long v) { intervalMs = v; }
        public int getInitialDays() { return initialDays; }
        public void setInitialDays(int v) { initialDays = v; }
        public List<Product> getProducts() { return products; }
        public void setProducts(List<Product> v) { products = v; }
    }

    /** Explicit CPE/application mapping; never infer distro package fixes from upstream CPEs. */
    public static class Product {
        private String cpePrefix = "", name = "", os = "", assetSource = "";
        public String getCpePrefix() { return cpePrefix; }
        public void setCpePrefix(String v) { cpePrefix = v; }
        public String getName() { return name; }
        public void setName(String v) { name = v; }
        public String getOs() { return os; }
        public void setOs(String v) { os = v; }
        public String getAssetSource() { return assetSource; }
        public void setAssetSource(String v) { assetSource = v; }
    }
}
