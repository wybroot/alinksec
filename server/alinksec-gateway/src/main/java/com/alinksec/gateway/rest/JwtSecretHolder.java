package com.alinksec.gateway.rest;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * JWT 密钥持有者：优先环境变量 ALINKSEC_JWT_SECRET；
 * 未配置则在 data 目录生成随机密钥持久化（容器需挂载 /app/data 卷）。
 */
@Component
public class JwtSecretHolder {

    @Value("${ALINKSEC_JWT_SECRET:}")
    private String fromEnv;

    @Value("${alinksec.server.cert-dir:./data/certs}")
    private String dataDir;

    private String secret;
    @Value("${alinksec.cluster.enabled:false}")
    private boolean clusterEnabled;

    @PostConstruct
    void init() throws IOException {
        if (fromEnv != null && !fromEnv.isBlank()) {
            if (clusterEnabled && fromEnv.length() < 32) throw new IllegalStateException("cluster_jwt_secret_too_short");
            secret = fromEnv;
            return;
        }
        Path parent = Path.of(dataDir).toAbsolutePath().getParent();
        if (parent == null) throw new IllegalStateException("jwt_secret_directory_invalid");
        Path keyFile = parent.resolve("jwt.secret");
        if (Files.exists(keyFile)) {
            secret = Files.readString(keyFile).trim();
            if (secret.isEmpty()) throw new IllegalStateException("jwt_secret_empty");
            if (clusterEnabled && secret.length() < 32) throw new IllegalStateException("cluster_jwt_secret_too_short");
            return;
        }
        if (clusterEnabled) throw new IllegalStateException("cluster_requires_initialized_shared_jwt");
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        secret = Base64.getEncoder().encodeToString(key);
        Files.createDirectories(keyFile.getParent());
        try {Files.createFile(keyFile,java.nio.file.attribute.PosixFilePermissions.asFileAttribute(java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")));}
        catch(UnsupportedOperationException ignored) {Files.createFile(keyFile);}
        Files.writeString(keyFile, secret);
    }

    public String secret() {
        return secret;
    }
}
