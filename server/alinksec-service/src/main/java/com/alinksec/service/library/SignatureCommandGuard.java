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
        var rows=jdbc.queryForList("SELECT db_version,package_key,sha256 FROM t_virus_db ORDER BY id DESC LIMIT 1");
        if (rows.size()!=1 || !rows.get(0).get("db_version").equals(command.getSignatureUpdate().getDbVersion())
                || !rows.get(0).get("sha256").equals(command.getSignatureUpdate().getSha256()))
            throw new IllegalArgumentException("特征库版本已被替代，不派发旧版本");
        String key=String.valueOf(rows.get(0).get("package_key"));
        String base=props.getSignature().getDownloadBaseUrl().replaceAll("/+$", "");
        String url=base+"/api/virus/db/download?packageKey="+java.net.URLEncoder.encode(key,java.nio.charset.StandardCharsets.UTF_8)
                +"&token="+tokens.issue(agentId,"virus-db",key);
        return command.toBuilder().setSignatureUpdate(command.getSignatureUpdate().toBuilder().setDownloadUrl(url)).build();
    }
}
