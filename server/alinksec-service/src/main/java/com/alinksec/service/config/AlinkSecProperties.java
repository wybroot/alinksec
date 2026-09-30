package com.alinksec.service.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 平台配置项（前缀 alinksec，见 application.yml）。
 */
@Component
@ConfigurationProperties(prefix = "alinksec")
public class AlinkSecProperties {

    private Server server = new Server();
    private Database database = new Database();
    private Policy policy = new Policy();
    private Metrics metrics = new Metrics();
    private Signature signature = new Signature();
    private Patch patch = new Patch();
    private Upgrade upgrade = new Upgrade();

    public Server getServer() { return server; }
    public Database getDatabase() { return database; }
    public Policy getPolicy() { return policy; }
    public Metrics getMetrics() { return metrics; }
    public Signature getSignature() { return signature; }
    public Patch getPatch() { return patch; }
    public Upgrade getUpgrade() { return upgrade; }

    /** 关系数据库后端：postgres / sqlite。 */
    public static class Database {
        private String type = "postgres";

        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
    }

    /** Agent 升级包（docs/01 §6.4：M4 本地磁盘存储，与 signature/patch 同模式） */
    public static class Upgrade {
        /** 升级包存储目录 */
        private String storageDir = "./data/agent-upgrade";
        /** Agent 下载基础地址（HTTPS 对外可达，含端口） */
        private String downloadBaseUrl = "https://127.0.0.1:8443";

        public String getStorageDir() { return storageDir; }
        public void setStorageDir(String storageDir) { this.storageDir = storageDir; }
        public String getDownloadBaseUrl() { return downloadBaseUrl; }
        public void setDownloadBaseUrl(String downloadBaseUrl) { this.downloadBaseUrl = downloadBaseUrl; }
    }

    /** gRPC 服务端 */
    public static class Server {
        /** gRPC 监听端口（Agent 连接） */
        private int port = 9443;
        /** 证书材料目录（CA/服务端证书首次启动自动生成） */
        private String certDir = "./data/certs";
        /** 仅供 TLS 反向代理读取的服务端证书目录（不包含 CA 私钥） */
        private String webTlsDir = "./data/web-tls";
        /** 服务端证书 SAN 列表 */
        private List<String> tlsSans = List.of("localhost", "127.0.0.1", "::1", "alinksec-server");
        /** Agent 可达的公网/内网 IPv4 或 DNS 名称；容器部署必填 */
        private String publicHost = "";
        /** Agent 证书有效期（天），设计文档 §6：10 年 */
        private int agentCertDays = 3650;

        public int getPort() { return port; }
        public void setPort(int port) { this.port = port; }
        public String getCertDir() { return certDir; }
        public void setCertDir(String certDir) { this.certDir = certDir; }
        public String getWebTlsDir() { return webTlsDir; }
        public void setWebTlsDir(String webTlsDir) { this.webTlsDir = webTlsDir; }
        public List<String> getTlsSans() { return tlsSans; }
        public void setTlsSans(List<String> tlsSans) { this.tlsSans = tlsSans; }
        public String getPublicHost() { return publicHost; }
        public void setPublicHost(String publicHost) { this.publicHost = publicHost; }
        public int getAgentCertDays() { return agentCertDays; }
        public void setAgentCertDays(int agentCertDays) { this.agentCertDays = agentCertDays; }
    }

    /** 策略 */
    public static class Policy {
        /** 当前全量策略版本（M2 接策略中心后由 t_protect_rule 变更触发递增） */
        private String currentVersion = "v0";

        public String getCurrentVersion() { return currentVersion; }
        public void setCurrentVersion(String currentVersion) { this.currentVersion = currentVersion; }
    }

    /** 指标出口（VictoriaMetrics） */
    public static class Metrics {
        private boolean enabled = false;
        private String vmBaseUrl = "http://127.0.0.1:8428";

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getVmBaseUrl() { return vmBaseUrl; }
        public void setVmBaseUrl(String vmBaseUrl) { this.vmBaseUrl = vmBaseUrl; }
    }

    /** 病毒特征库（docs/05 §1.2：M2 本地磁盘存储，M3 演进 MinIO 预签名） */
    public static class Signature {
        /** 特征包存储目录 */
        private String storageDir = "./data/signature";
        /** Agent 下载基础地址（REST 对外可达，含端口） */
        private String downloadBaseUrl = "https://127.0.0.1:8443";

        public String getStorageDir() { return storageDir; }
        public void setStorageDir(String storageDir) { this.storageDir = storageDir; }
        public String getDownloadBaseUrl() { return downloadBaseUrl; }
        public void setDownloadBaseUrl(String downloadBaseUrl) { this.downloadBaseUrl = downloadBaseUrl; }
    }

    /** 离线补丁仓库（docs/05 §3.4：补丁包本地磁盘存储 + 下载端点分发） */
    public static class Patch {
        /** 补丁包存储目录 */
        private String storageDir = "./data/patch";
        /** Agent 下载基础地址（与 signature.downloadBaseUrl 一致，REST 对外可达） */
        private String downloadBaseUrl = "https://127.0.0.1:8443";

        public String getStorageDir() { return storageDir; }
        public void setStorageDir(String storageDir) { this.storageDir = storageDir; }
        public String getDownloadBaseUrl() { return downloadBaseUrl; }
        public void setDownloadBaseUrl(String downloadBaseUrl) { this.downloadBaseUrl = downloadBaseUrl; }
    }
}
