package com.alinksec.service.virus;

import com.alinksec.service.library.LibraryCatalog;
import com.alinksec.service.library.LibraryFiles;
import com.alinksec.service.library.LibraryProperties;
import com.alinksec.service.library.SignaturePackage;
import com.alinksec.service.config.AlinkSecProperties;
import com.alinksec.service.download.AgentDownloadTokenService;
import com.alinksec.proto.CmdSignatureUpdate;
import com.alinksec.proto.Command;
import com.alinksec.service.command.CommandService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * 病毒特征库管理（docs/05 §1.2）：
 * 导入（zip：manifest.json + hashes.txt）→ 本地磁盘存储 → t_virus_db 版本记录 → 推送 CmdSignatureUpdate。
 *
 * 版本比对：Agent 心跳携带 db_version（proto v8），落后于平台当前版本即按需下发
 * CmdSignatureUpdate；另有「导入后立即推送 + 定时兜底推送」，Agent 端幂等（版本一致直接 ACK DONE）。
 */
@Service
public class VirusDbService {

    private static final Logger log = LoggerFactory.getLogger(VirusDbService.class);

    private final JdbcTemplate jdbc;
    private final CommandService commandService;
    private final AlinkSecProperties props;
    private final AgentDownloadTokenService downloadTokens;
    private final LibraryCatalog catalog;
    private final LibraryFiles files;
    private final LibraryProperties libraries;

    public VirusDbService(JdbcTemplate jdbc, CommandService commandService, AlinkSecProperties props,
                          AgentDownloadTokenService downloadTokens, LibraryCatalog catalog, LibraryFiles files, LibraryProperties libraries) {
        this.jdbc = jdbc;
        this.commandService = commandService;
        this.props = props;
        this.downloadTokens = downloadTokens;
        this.catalog = catalog;
        this.files = files;
        this.libraries = libraries;
    }

    /**
     * 导入特征库包：解析校验 zip 结构 → 落盘 → 记录版本 → 推送全部 Agent。
     * 返回 {dbVersion, hashCount, ruleCount}。
     */
    public Map<String, Object> importPackage(InputStream in, Long importedBy) throws IOException {
        Path tmp = files.temporary(".zip");
        try {
            try (InputStream input = in; var out = Files.newOutputStream(tmp)) {
                byte[] buffer = new byte[8192];
                long size = 0;
                int n;
                while ((n = input.read(buffer)) != -1) {
                    size += n;
                    if (size > libraries.getMaxDownloadBytes()) throw new IllegalArgumentException("特征包超过大小上限");
                    out.write(buffer, 0, n);
                }
            }
            var result = catalog.signatures("manual", SignaturePackage.read(tmp, libraries), true, importedBy);
            if (Boolean.TRUE.equals(result.get("changed"))) pushToAllAgents();
            return result;
        } finally { Files.deleteIfExists(tmp); }
    }

    public LibraryFiles.Download downloadPackage(String key) throws IOException {
        return files.download("signature", key);
    }

    /** Agent 下载 URL（package_key 为版本号文件名，不可猜测性由版本号语义承担 + 内网部署） */
    public String downloadUrl(String agentId, String packageKey) {
        String base = props.getSignature().getDownloadBaseUrl().replaceAll("/+$", "");
        return base + "/api/virus/db/download?packageKey=" + packageKey
                + "&token=" + downloadTokens.issue(agentId, "virus-db", packageKey);
    }

    /** 推送最新特征库给全部 Agent（在线即达，离线指令挂起） */
    public void pushToAllAgents() {
        Map<String, Object> latest = latestDb();
        if (latest == null) {
            return;
        }
        List<String> agents = jdbc.queryForList(
                "SELECT agent_id FROM t_agent WHERE deleted = false", String.class);
        for (String agentId : agents) {
            dispatchUpdate(agentId, latest);
        }
        log.info("特征库更新指令已下发: version={} agents={}", latest.get("db_version"), agents.size());
    }

    /** 定时兜底推送（新装 Agent 上线后最长 interval 内拿到最新库；Agent 幂等跳过已装版本） */
    @Scheduled(fixedDelayString = "${alinksec.signature.push-interval-ms:3600000}",
            initialDelayString = "${alinksec.signature.push-interval-ms:3600000}")
    public void scheduledPush() {
        Map<String, Object> latest = latestDb();
        if (latest != null) {
            pushToAllAgents();
        }
    }

    /**
     * 心跳版本比对触发更新（docs/05 §1.2）：Agent db_version 落后/未装时下发更新指令。
     * Agent 幂等（版本一致 ACK DONE），故重复下发无害。
     */
    public void pushIfOutdated(String agentId, String agentDbVersion) {
        Map<String, Object> latest = latestDb();
        if (latest == null) {
            return;
        }
        String latestVersion = (String) latest.get("db_version");
        if (!latestVersion.equals(agentDbVersion == null ? "" : agentDbVersion)) {
            log.info("特征库版本落后，下发更新: agent={} agent_db={} latest={}",
                    agentId, agentDbVersion, latestVersion);
            dispatchUpdate(agentId, latest);
        }
    }

    private void dispatchUpdate(String agentId, Map<String, Object> db) {
        commandService.dispatch(agentId, Command.newBuilder()
                .setSignatureUpdate(CmdSignatureUpdate.newBuilder()
                        .setDbVersion((String) db.get("db_version"))
                        .setDownloadUrl(downloadUrl(agentId, (String) db.get("package_key")))
                        .setSha256((String) db.get("sha256"))),
                null);
    }

    private Map<String, Object> latestDb() {
        List<Map<String, Object>> rows = jdbc.queryForList("""
                SELECT db_version, package_key, sha256 FROM t_virus_db ORDER BY id DESC LIMIT 1
                """);
        return rows.isEmpty() ? null : rows.get(0);
    }

}
