package com.alinksec.service.baseline;

import org.springframework.jdbc.core.JdbcTemplate;
import java.util.*;

/** Serialized with upstream imports/withdrawals; never gates an already published task. */
final class BaselineUpstreamGuard {
    private BaselineUpstreamGuard() {}
    static void lock(JdbcTemplate jdbc){jdbc.update("UPDATE t_baseline_upstream_gate SET revision=revision+1 WHERE id=1");}
    static List<Map<String,Object>> provenance(JdbcTemplate jdbc,String kind,String id){
        return jdbc.queryForList("""
                SELECT r.source_id,r.id AS release_id,r.remote_status,r.sha256 AS download_sha256,
                       a.sequence,a.payload_sha256,a.key_sha256,a.expires_at,s.configured,
                       a.config_hash AS receipt_config,s.config_hash AS source_config
                FROM t_baseline_upstream_release r JOIN t_baseline_upstream_receipt a ON a.id=r.current_receipt
                JOIN t_baseline_upstream_source s ON s.id=r.source_id WHERE r.kind=? AND r.package_id=?
                """,kind,id);
    }
    static void requireAdoptable(JdbcTemplate jdbc,String kind,String id){
        for(var row:provenance(jdbc,kind,id)){
            if(!row.get("remote_status").equals("active")||((Number)row.get("configured")).intValue()!=1
                    ||!row.get("receipt_config").equals(row.get("source_config"))||((Number)row.get("expires_at")).longValue()<=System.currentTimeMillis())
                throw new IllegalArgumentException("上游内容已撤回、来源配置已变更或签名索引已过期，请先同步有效索引");
        }
    }
}
