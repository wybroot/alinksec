package com.alinksec.service.fix;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.scan.VulnerabilityEvidence;
import org.springframework.jdbc.core.JdbcTemplate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Shared checks for initial dispatch and every subsequent delivery attempt. */
final class PackageRepairValidation {
    private final JdbcTemplate jdbc;
    private final PatchRepoService patches;
    PackageRepairValidation(JdbcTemplate jdbc, PatchRepoService patches) { this.jdbc=jdbc; this.patches=patches; }

    Map<String,Object> validate(Map<String,Object> target) {
        var payload = new LinkedHashMap<>(JsonUtils.read(String.valueOf(target.get("fix_payload")),Map.class));
        String agentId = String.valueOf(target.get("agent_id"));
        if (!String.valueOf(target.get("ref_id")).equals(String.valueOf(payload.get("finding_id"))))
            throw new IllegalArgumentException("任务项与漏洞引用不一致");
        if (!(payload.get("inventory") instanceof Map<?,?> identity)
                || !identity.equals(identity(agentId,String.valueOf(payload.get("pkg_name")),String.valueOf(identity.get("installed_version")))))
            throw new IllegalArgumentException("软件资产身份已变化或缺少完整采集证据，请重新采集并创建修复任务");
        var rows = jdbc.queryForList("""
                SELECT source,architecture,distro_id,distro_version,identity_status,installed_version,
                  os_type AS finding_os_type,os_version AS finding_os_version,status,current_match,software,cve_id,fixed_version,
                  rule_source_id,rule_digest,evidence_status FROM t_vuln_finding WHERE id=? AND agent_id=?
                """,Long.parseLong(String.valueOf(target.get("ref_id"))),agentId);
        if (rows.size()!=1) throw new IllegalArgumentException("漏洞结果不存在或不属于该主机");
        var finding = rows.get(0);
        if (((Number)finding.get("status")).intValue()>1 || !com.alinksec.service.config.DatabaseDialect.readBoolean(finding.get("current_match"))
                || !Objects.equals(payload.get("pkg_name"),finding.get("software"))
                || !Objects.equals(payload.get("cve_id"),finding.get("cve_id"))
                || !Objects.equals(payload.get("target_version"),finding.get("fixed_version"))
                || !Objects.equals(payload.get("rule_source_id"),finding.get("rule_source_id"))
                || !Objects.equals(payload.get("rule_digest"),finding.get("rule_digest")))
            throw new IllegalArgumentException("漏洞结果或修复目标已变化，请重新扫描并创建修复任务");
        findingIdentity(finding,identity); evidence(finding);
        var scope = new LinkedHashMap<>(payload); scope.put("agent_id",agentId);
        var patch = patches.verifyPin(payload.get("patch_review") instanceof Map<?,?> pin ? pin : null,scope);
        if (!Objects.equals(payload.get("sha256"),patch.get("sha256")) || !Objects.equals(payload.get("repo_type"),patch.get("repo_type")))
            throw new IllegalArgumentException("任务二进制包摘要或格式与固定对象不一致");
        payload.put("validated_patch",patch);
        return payload;
    }

    Map<String,Object> identity(String agentId,String name,String version) {
        jdbc.update("UPDATE t_agent SET software_revision=software_revision WHERE agent_id=? AND deleted=false",agentId);
        var hosts=jdbc.queryForList("""
                SELECT os_type,os_version,distro_id,distro_version,software_collection_status,software_identity_error,package_repair_contract
                FROM t_agent WHERE agent_id=? AND deleted=false
                """,agentId);
        if (hosts.size()!=1 || !"complete".equals(hosts.get(0).get("software_collection_status")))
            throw new IllegalArgumentException("软件清单采集失败或完整性未知，请先重新采集: "+agentId);
        var host=hosts.get(0);
        var packages=jdbc.queryForList("SELECT version,source,architecture FROM t_asset_software WHERE agent_id=? AND name=?",agentId,name);
        if (packages.size()!=1 || !version.equals(packages.get(0).get("version")))
            throw new IllegalArgumentException("软件包已变化、存在多个架构或多个安装版本，需人工处理: "+name);
        var pkg=packages.get(0);
        int type=((Number)host.get("os_type")).intValue();
        if (type!=1 || ((Number)host.get("package_repair_contract")).intValue()!=2)
            throw new IllegalArgumentException("该 Agent 未声明受支持的软件包执行校验能力，请更新支持该系统的 Agent 或人工处理");
        String source=String.valueOf(pkg.get("source")), architecture=String.valueOf(pkg.get("architecture"));
        String distro=String.valueOf(host.get("distro_id")), release=String.valueOf(host.get("distro_version"));
        if (!java.util.Set.of("rpm","dpkg").contains(source) || architecture.isBlank() || distro.isBlank() || release.isBlank()
                || !"".equals(host.get("software_identity_error"))) throw new IllegalArgumentException("缺少发行版、包来源或包架构身份，需人工处理: "+name);
        return Map.of("contract",2,"source",source,"architecture",architecture,"distro_id",distro,"distro_version",release,
                "installed_version",version,"os_type",type,"os_version",host.get("os_version")==null ? "" : host.get("os_version"));
    }

    void evidence(Map<String,Object> finding) {
        var rules=jdbc.queryForList("SELECT rule_source_id,rule_digest,CAST(affected AS TEXT) AS affected FROM t_cve_db WHERE cve_id=?",finding.get("cve_id"));
        if (!"declared".equals(finding.get("evidence_status")) || rules.size()!=1
                || !new com.alinksec.service.library.LibrarySelection(jdbc).allowsCve(String.valueOf(finding.get("cve_id")),
                    String.valueOf(finding.get("rule_source_id")),String.valueOf(finding.get("rule_digest")))
                || !Objects.equals(finding.get("rule_source_id"),rules.get(0).get("rule_source_id"))
                || !Objects.equals(finding.get("rule_digest"),rules.get(0).get("rule_digest"))
                || !String.valueOf(finding.get("rule_digest")).matches("[a-f0-9]{64}")
                || !finding.get("rule_digest").equals(VulnerabilityEvidence.ruleDigest(String.valueOf(rules.get(0).get("rule_source_id")),
                String.valueOf(finding.get("cve_id")),JsonUtils.read((String)rules.get(0).get("affected")))))
            throw new IllegalArgumentException("漏洞规则依据缺失、冲突或已变化，请重新扫描并人工核对来源");
    }

    static void findingIdentity(Map<String,Object> finding,Map<?,?> identity) {
        if (!"complete".equals(finding.get("identity_status"))) throw new IllegalArgumentException("漏洞记录缺少匹配时的软件身份，请重新扫描后创建修复任务");
        for (String field:List.of("source","architecture","distro_id","distro_version","installed_version"))
            if (!Objects.equals(finding.get(field),identity.get(field))) throw new IllegalArgumentException("漏洞记录与当前软件资产身份不一致，请重新扫描后创建修复任务");
        if (!(finding.get("finding_os_type") instanceof Number type) || !(identity.get("os_type") instanceof Number current)
                || type.intValue()!=current.intValue() || !Objects.equals(finding.get("finding_os_version"),identity.get("os_version")))
            throw new IllegalArgumentException("漏洞记录与当前系统身份不一致，请重新扫描后创建修复任务");
    }
}
