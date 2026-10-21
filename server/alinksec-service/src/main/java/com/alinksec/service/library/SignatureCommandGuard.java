package com.alinksec.service.library;

import com.alinksec.proto.Command;
import com.alinksec.service.command.CommandLifecycleListener;
import com.alinksec.service.config.AlinkSecProperties;
import com.alinksec.service.download.AgentDownloadTokenService;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/** Obsolete queued releases cannot restore retired intelligence; current replay receives a fresh token. */
@Component
public class SignatureCommandGuard implements CommandLifecycleListener {
    private final JdbcTemplate jdbc;
    private final AgentDownloadTokenService tokens;
    private final AlinkSecProperties props;
    public SignatureCommandGuard(JdbcTemplate jdbc,AgentDownloadTokenService tokens,AlinkSecProperties props) {
        this.jdbc=jdbc; this.tokens=tokens; this.props=props;
    }
    @Override public Command prepareDelivery(String agentId,Command command) {
        if (!command.hasSignatureUpdate()) return command;
        jdbc.update("UPDATE t_security_feed_state SET cursor=cursor WHERE source_id='_signature-release'");
        var rows=jdbc.queryForList("SELECT * FROM t_virus_db ORDER BY id DESC LIMIT 1");
        if (rows.size()!=1 || !rows.get(0).get("db_version").equals(command.getSignatureUpdate().getDbVersion())
                || !rows.get(0).get("sha256").equals(command.getSignatureUpdate().getSha256()))
            throw new IllegalArgumentException("特征库版本已被替代，不派发旧版本");
        var release=rows.get(0);
        String key=String.valueOf(release.get("package_key"));
        var update=command.getSignatureUpdate().toBuilder().setDownloadUrl(url(agentId,key))
                .clearUpdateContract().clearContentSha256().clearDeltaUrl().clearDeltaSha256().clearBaseVersion().clearBaseContentSha256();
        var agents=jdbc.queryForList("SELECT signature_update_contract,virus_db_version FROM t_agent WHERE agent_id=? AND deleted=false",agentId);
        String content=String.valueOf(release.get("content_sha256"));
        if (agents.size()==1 && ((Number)agents.get(0).get("signature_update_contract")).intValue()==1 && content.matches("[a-f0-9]{64}")) {
            update.setUpdateContract(1).setContentSha256(content);
            String deltaKey=String.valueOf(release.get("delta_key"));
            if (!deltaKey.isEmpty() && release.get("delta_base_version").equals(agents.get(0).get("virus_db_version"))) {
                update.setDeltaUrl(url(agentId,deltaKey)).setDeltaSha256(String.valueOf(release.get("delta_sha256")))
                        .setBaseVersion(String.valueOf(release.get("delta_base_version")))
                        .setBaseContentSha256(String.valueOf(release.get("delta_base_content_sha256")));
            }
        }
        return command.toBuilder().setSignatureUpdate(update).build();
    }
    private String url(String agentId,String key) {
        String base=props.getSignature().getDownloadBaseUrl().replaceAll("/+$", "");
        return base+"/api/virus/db/download?packageKey="+java.net.URLEncoder.encode(key,java.nio.charset.StandardCharsets.UTF_8)
                +"&token="+tokens.issue(agentId,"virus-db",key);
    }
}
