package com.alinksec.service.cluster;

import com.alinksec.service.config.DatabaseDialect;
import jakarta.annotation.PostConstruct;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/** External coordination is opt-in; SQLite and ordinary single-node installs need neither broker. */
@Component
@ConfigurationProperties(prefix = "alinksec.cluster")
public class ClusterProperties {
    private final DatabaseDialect database;
    private boolean enabled;
    private String deploymentId = "", nodeId = "", sharedDir = "", redisUri = "", rabbitUri = "";
    private long leaseMs = 45_000;
    private int maxPendingReports = 10_000;
    private long maxPendingBytes = 128L << 20;
    private int maxReportBytes = 1 << 20;
    private int maxHistoryReports = 500_000;
    private long dedupRetentionMs = 600_000;

    public ClusterProperties(DatabaseDialect database) { this.database = database; }

    @PostConstruct
    public void validate() {
        if (!enabled) return;
        if (database.isSqlite()) throw new IllegalStateException("cluster_requires_postgresql");
        if (!deploymentId.matches("[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}")
                || !nodeId.matches("[A-Za-z0-9][A-Za-z0-9_-]{0,63}") || sharedDir.isBlank())
            throw new IllegalStateException("cluster_identity_or_shared_directory_missing");
        if (leaseMs < 15_000 || leaseMs > 120_000 || maxPendingReports < 10 || maxPendingReports > 100_000
                || maxReportBytes < 1024 || maxReportBytes > 4 << 20
                || maxPendingBytes < maxReportBytes || maxPendingBytes > 1L << 30
                || maxHistoryReports<maxPendingReports || maxHistoryReports>1_000_000
                || dedupRetentionMs<600_000 || dedupRetentionMs>86_400_000)
            throw new IllegalStateException("cluster_capacity_or_lease_invalid");
        validateUri(redisUri, java.util.Set.of("redis", "rediss"), false);
        validateUri(rabbitUri, java.util.Set.of("amqp", "amqps"), true);
    }

    private static void validateUri(String text, java.util.Set<String> schemes, boolean rabbit) {
        try {
            var uri = java.net.URI.create(text);
            String credentials = uri.getUserInfo();
            if (!schemes.contains(uri.getScheme()) || uri.getHost() == null || uri.getFragment() != null
                    || credentials == null || !credentials.contains(":")) throw new IllegalArgumentException();
            String user = credentials.substring(0, credentials.indexOf(':'));
            String password = credentials.substring(credentials.indexOf(':') + 1);
            if (password.length() < 16 || rabbit && (user.isBlank() || user.equals("guest")))
                throw new IllegalArgumentException();
        } catch (RuntimeException failure) {
            throw new IllegalStateException(rabbit ? "cluster_rabbit_credentials_invalid" : "cluster_redis_credentials_invalid");
        }
    }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean value) { enabled = value; }
    public String getDeploymentId() { return deploymentId; }
    public void setDeploymentId(String value) { deploymentId = value; }
    public String getNodeId() { return nodeId; }
    public void setNodeId(String value) { nodeId = value; }
    public String getSharedDir() { return sharedDir; }
    public void setSharedDir(String value) { sharedDir = value; }
    public String getRedisUri() { return redisUri; }
    public void setRedisUri(String value) { redisUri = value; }
    public String getRabbitUri() { return rabbitUri; }
    public void setRabbitUri(String value) { rabbitUri = value; }
    public long getLeaseMs() { return leaseMs; }
    public void setLeaseMs(long value) { leaseMs = value; }
    public int getMaxPendingReports() { return maxPendingReports; }
    public void setMaxPendingReports(int value) { maxPendingReports = value; }
    public long getMaxPendingBytes() { return maxPendingBytes; }
    public void setMaxPendingBytes(long value) { maxPendingBytes = value; }
    public int getMaxReportBytes() { return maxReportBytes; }
    public void setMaxReportBytes(int value) { maxReportBytes = value; }
    public int getMaxHistoryReports() { return maxHistoryReports; }
    public void setMaxHistoryReports(int value) { maxHistoryReports=value; }
    public long getDedupRetentionMs() { return dedupRetentionMs; }
    public void setDedupRetentionMs(long value) { dedupRetentionMs=value; }
}
