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

    @PostConstruct
    void init() throws IOException {
        if (fromEnv != null && !fromEnv.isBlank()) {
            secret = fromEnv;
            return;
        }
        Path keyFile = Path.of(dataDir).getParent().resolve("jwt.secret");
        if (Files.exists(keyFile)) {
            secret = Files.readString(keyFile).trim();
            return;
        }
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        secret = Base64.getEncoder().encodeToString(key);
        Files.createDirectories(keyFile.getParent());
        Files.writeString(keyFile, secret);
    }

    public String secret() {
        return secret;
    }
}
