package com.alinksec.service.fix;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.CmdVulnFix;
import com.alinksec.proto.Command;
import com.alinksec.proto.FixItem;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.config.DatabaseDialect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.Duration;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 配置类一键修复任务编排（docs/05 §3）：
 * 目标来自基线核查失败项（t_baseline_item.fix_spec）。
 * risk=manual 的项不支持自动修复（需人工）；payload = fix_spec + check 合并（Agent 复核用）。
 */
@Service
public class FixTaskService {

    private static final Logger log = LoggerFactory.getLogger(FixTaskService.class);
    private static final DateTimeFormatter NO_FMT = DateTimeFormatter.ofPattern("yyyyMMddHHmmss");

    private final JdbcTemplate jdbc;
    private final CommandService commandService;
    private final PatchRepoService patchRepo;
    private final DatabaseDialect database;
    private final PackageRepairValidation validation;
    private final org.springframework.transaction.support.TransactionTemplate transaction;

    public FixTaskService(JdbcTemplate jdbc, CommandService commandService, PatchRepoService patchRepo,
                          DatabaseDialect database, org.springframework.transaction.PlatformTransactionManager transactionManager) {
        this.jdbc = jdbc;
        this.commandService = commandService;
        this.patchRepo = patchRepo;
        this.database = database;
        this.validation = new PackageRepairValidation(jdbc,patchRepo);
        this.transaction = new org.springframework.transaction.support.TransactionTemplate(transactionManager);
    }

    /**
     * 创建并下发修复任务。
     *
     * @param name     任务名
     * @param items    修复目标：agentId + itemId（t_baseline_item.id，须有 fix_spec）
     * @param createdBy 创建人
     * @return 任务 id
     */
    @Transactional
    public long createTask(String name, List<Map<String, Object>> items, Long createdBy) {
        if (items == null || items.isEmpty() || items.size() > 500) {
            throw new IllegalArgumentException("请选择 1 至 500 项修复目标");
        }
        // 归一化输入：agentId + itemId
        record Target(String agentId, long itemId) {}
        List<Target> targets = new ArrayList<>();
        for (Map<String, Object> it : items) {
            String agentId = it.get("agentId") instanceof String value ? value : "";
            long itemId = it.get("itemId") instanceof Number n ? n.longValue() : -1;
            if (agentId.isBlank() || itemId <= 0) {
                throw new IllegalArgumentException("修复项格式非法（需 agentId + itemId）");
            }
            targets.add(new Target(agentId, itemId));
        }

        // 基线项快照：fix_spec + check（一次查全，去重 itemId）
        List<Long> itemIds = targets.stream().map(Target::itemId).distinct().toList();
        jdbc.queryForList("""
                SELECT DISTINCT p.code FROM t_baseline_item i JOIN t_baseline_template t ON t.id=i.template_id
                JOIN t_baseline_package p ON p.id=t.package_id WHERE i.id IN (%s) ORDER BY p.code
                """.formatted(DatabaseDialect.placeholders(itemIds.size())), String.class, itemIds.toArray())
                .forEach(code -> jdbc.update("UPDATE t_baseline_package_gate SET revision=revision+1 WHERE code=?", code));
        Map<Long, Map<String, Object>> specs = new LinkedHashMap<>();
        for (Map<String, Object> row : jdbc.queryForList("""
                SELECT i.id, i.code, i.name, CAST(i.fix_spec AS TEXT) AS fix_spec,
                       CAST(i."check" AS TEXT) AS "check",t.os_type,t.os_version_pattern
                FROM t_baseline_item i JOIN t_baseline_template t ON t.id=i.template_id
                WHERE i.enabled AND t.enabled AND i.id IN (%s)
                """.formatted(DatabaseDialect.placeholders(itemIds.size())), itemIds.toArray())) {
            specs.put(((Number) row.get("id")).longValue(), row);
        }

        // 校验 + 构造下发内容
        Map<String, List<FixItem>> byAgent = new LinkedHashMap<>();
        List<Map<String, Object>> targetRows = new ArrayList<>();
        for (Target t : targets) {
            Map<String, Object> spec = specs.get(t.itemId());
            if (spec == null) {
                throw new IllegalArgumentException("基线项不存在、未启用或模板已撤回: " + t.itemId());
            }
            var host = jdbc.queryForList("SELECT os_type,os_version FROM t_agent WHERE agent_id=? AND deleted=false", t.agentId());
            if (host.size() != 1 || !com.alinksec.service.baseline.BaselinePackageFormat.applies(
                    ((Number) spec.get("os_type")).intValue(), (String) spec.get("os_version_pattern"), host.get(0))) {
                throw new IllegalArgumentException("基线修复不适用于当前主机系统: " + t.agentId());
            }
            var evidence = jdbc.queryForList("""
                    SELECT r.passed,i.fix_current FROM t_baseline_result r
                    JOIN v_baseline_result_definition i ON i.result_id=r.id
                    WHERE r.agent_id=? AND r.item_id=? ORDER BY r.task_id DESC,r.id DESC LIMIT 1
                    """, t.agentId(), t.itemId());
            if (evidence.isEmpty() || DatabaseDialect.readBoolean(evidence.get(0).get("passed"))
                    || !DatabaseDialect.readBoolean(evidence.get(0).get("fix_current"))) {
                throw new IllegalArgumentException("缺少适用的未通过核查结果，或结果定义已过期，请重新核查: " + t.itemId());
            }
            String fixSpec = (String) spec.get("fix_spec");
            if (fixSpec == null || fixSpec.isBlank() || "null".equals(fixSpec)) {
                throw new IllegalArgumentException("基线项 " + spec.get("code") + " 不支持自动修复（无 fix_spec）");
            }
            String risk = JsonUtils.read(fixSpec).path("risk").asText("auto");
            if ("manual".equals(risk)) {
                throw new IllegalArgumentException("基线项 " + spec.get("code") + " 风险等级为 manual，需人工修复");
            }
            // payload：fix_spec 与 check 合并（Agent 修复后重跑 check 复核）
            Map<String, Object> payload = JsonUtils.read(fixSpec, Map.class);
            payload.put("check", spec.get("check"));
            byAgent.computeIfAbsent(t.agentId(), k -> new ArrayList<>())
                    .add(FixItem.newBuilder()
                            .setRefId(String.valueOf(t.itemId()))
                            .setType(FixItem.FixType.CONFIG)
                            .setPayload(JsonUtils.write(payload))
                            .build());
            targetRows.add(Map.of("ref_type", "baseline_item",
                    "ref_id", String.valueOf(t.itemId()),
                    "agent_id", t.agentId(),
                    "fix_payload", JsonUtils.write(payload)));
        }

        // 主机存在性校验
        List<String> agentIds = List.copyOf(byAgent.keySet());
        Integer exists = jdbc.queryForObject(
                "SELECT count(*) FROM t_agent WHERE agent_id IN ("
                        + DatabaseDialect.placeholders(agentIds.size()) + ") AND deleted = false",
                Integer.class, agentIds.toArray());
        if (exists == null || exists != agentIds.size()) {
            throw new IllegalArgumentException("部分主机不存在或已删除，请刷新后重选");
        }

        String taskNo = "FX" + LocalDateTime.now().format(NO_FMT)
                + ThreadLocalRandom.current().nextInt(100, 1000);
        long taskId = jdbc.queryForObject(
                "INSERT INTO t_fix_task (task_no, name, type, scope, targets, status, created_by) "
                        + "VALUES (?, ?, 1, ?, ?, 1, ?) RETURNING id",
                Long.class, taskNo,
                name == null || name.isBlank() ? taskNo + " 配置修复" : name,
                JsonUtils.write(Map.of("agent_ids", agentIds)),
                JsonUtils.write(targetRows), createdBy);
        jdbc.update("UPDATE t_fix_task SET started_at = CURRENT_TIMESTAMP WHERE id = ?", taskId);

        // 预写 t_fix_record（待执行），结果上报按 task+agent+ref 更新
        for (Map<String, Object> row : targetRows) {
            jdbc.update("""
                    INSERT INTO t_fix_record (task_id, agent_id, ref_id, ref_type)
                    VALUES (?, ?, ?, 'baseline_item')
                    """, taskId, row.get("agent_id"), row.get("ref_id"));
        }

        for (var e : byAgent.entrySet()) {
            commandService.dispatchAfterCommit(e.getKey(), Command.newBuilder()
                    .setVulnFix(CmdVulnFix.newBuilder()
                            .setTaskId(String.valueOf(taskId))
                            .addAllFixes(e.getValue())),
                    createdBy);
        }
        log.info("配置修复任务已下发: task_id={} task_no={} agents={} items={}",
                taskId, taskNo, agentIds.size(), targets.size());
        return taskId;
    }

    /** 任务超时兜底：执行中超 30 分钟 → 部分失败（已收结果保留） */
    @Scheduled(fixedDelay = 120_000, initialDelay = 150_000)
    public void sweepTimeout() {
        var ids=jdbc.queryForList("SELECT id FROM t_fix_task WHERE status=1 AND COALESCE(started_at,created_at)<? ORDER BY id LIMIT 100",Long.class,database.timestampBefore(Duration.ofMinutes(30)));
        for (Long id:ids) {
            transaction.executeWithoutResult(status -> {
                var task=lockedTask(id);
                if (((Number)task.get("status")).intValue()==1) stopTask(id,3,"派发后 30 分钟未完成，停止排队和重推；已开始的安装需人工检查",null);
            });
        }
    }

    /* ================================================================
     * 软件包类修复（docs/05 §3.3）：审批 + 维护窗口 + 补丁覆盖率校验
     * ================================================================ */

    /**
     * 创建软件包类修复任务（不立即下发；审批通过且进入维护窗口后由 dispatchApproved 派发）。
     *
     * @param items       [{agentId, findingId}]（t_vuln_finding，须有 fixed_version）
     * @param approver    审批人（必填）
     * @param windowStart 维护窗口起（ISO 本地时间，空 = 审批后立即执行）
     * @param windowEnd   维护窗口止（填写窗口时必须提供，限制派发与重推）
     */
    @Transactional
    public Map<String, Object> createPackageTask(String name, List<Map<String, Object>> items,
                                                 String approver, String windowStart, String windowEnd,
                                                 Long createdBy) {
        if (items == null || items.isEmpty() || items.size()>500) {
            throw new IllegalArgumentException("请选择 1 至 500 项修复目标");
        }
        if (approver == null || approver.isBlank()) {
            throw new IllegalArgumentException("软件包类修复必须指定审批人");
        }
        // 漏洞快照：finding + 主机 OS + 目标版本
        List<Long> findingIds = items.stream()
                .map(it -> it.get("findingId") instanceof Number n ? n.longValue() : -1L)
                .filter(id -> id > 0).distinct().toList();
        if (findingIds.size() != items.size() || findingIds.isEmpty()) {
            throw new IllegalArgumentException("修复项格式非法（需 agentId + findingId）");
        }
        requireActor(createdBy);
        var reviewers=jdbc.queryForList("""
                SELECT u.id,u.username FROM t_user u JOIN t_role r ON r.id=u.role_id
                WHERE u.username=? AND u.status=1 AND r.name IN ('admin','operator')
                """,approver.trim());
        if (reviewers.size()!=1) throw new IllegalArgumentException("审批人必须是已启用的管理员或运维账号");
        long approverId=((Number)reviewers.get(0).get("id")).longValue();
        approver=String.valueOf(reviewers.get(0).get("username"));
        OffsetDateTime ws=parseTime(windowStart),we=parseTime(windowEnd);
        if ((ws==null)!=(we==null) || ws!=null && (!we.isAfter(ws) || !we.isAfter(OffsetDateTime.now())))
            throw new IllegalArgumentException("维护窗口必须同时提供起止时间，结束晚于开始且尚未过期");
        items.stream().map(it -> String.valueOf(it.get("agentId"))).distinct().sorted().forEach(agent ->
                jdbc.update("UPDATE t_agent SET software_revision=software_revision WHERE agent_id=? AND deleted=false",agent));
        Map<Long, Map<String, Object>> findings = new LinkedHashMap<>();
        for (Map<String, Object> row : jdbc.queryForList("""
                SELECT f.id, f.agent_id, f.cve_id, f.software, f.installed_version, f.fixed_version, f.status,f.current_match,
                       f.source,f.architecture,f.distro_id,f.distro_version,f.identity_status,
                        f.os_type AS finding_os_type,f.os_version AS finding_os_version,
                        f.rule_source_id,f.rule_digest,f.evidence_status,
                       a.os_type, a.os_version
                FROM t_vuln_finding f JOIN t_agent a ON a.agent_id = f.agent_id AND a.deleted = false
                WHERE f.id IN (%s)
                """.formatted(DatabaseDialect.placeholders(findingIds.size())), findingIds.toArray())) {
            findings.put(((Number) row.get("id")).longValue(), row);
        }

        // 覆盖率校验 + payload 构造
        List<Map<String, Object>> resolveTargets = new ArrayList<>();
        var packageKeys=new java.util.HashSet<String>();
        for (Map<String, Object> it : items) {
            String agentId = String.valueOf(it.get("agentId"));
            long fid = it.get("findingId") instanceof Number n ? n.longValue() : -1;
            Map<String, Object> f = findings.get(fid);
            if (f == null || !agentId.equals(String.valueOf(f.get("agent_id")))) {
                throw new IllegalArgumentException("漏洞项不存在或与主机不匹配: finding=" + fid);
            }
            if (((Number) f.get("status")).intValue() > 1 || !DatabaseDialect.readBoolean(f.get("current_match"))) {
                throw new IllegalArgumentException("漏洞项已处置，请刷新后重选: finding=" + fid);
            }
            if (!packageKeys.add(JsonUtils.write(List.of(agentId,f.get("software")))))
                throw new IllegalArgumentException("同一主机的软件包请只选择一个当前修复目标；修复后重新扫描评估其他 CVE");
            Integer active=jdbc.queryForObject("""
                    SELECT count(*) FROM t_fix_record r JOIN t_fix_task t ON t.id=r.task_id
                    JOIN t_vuln_finding f ON CAST(f.id AS TEXT)=r.ref_id AND f.agent_id=r.agent_id
                    WHERE r.agent_id=? AND f.software=? AND r.ref_type='vuln_finding' AND r.status=0 AND t.status IN (0,1)
                    """,Integer.class,agentId,f.get("software"));
            if (active!=null && active>0) throw new IllegalArgumentException("该软件包已有待审批或执行中的修复任务，请先查看原任务");
            if (f.get("fixed_version") == null || String.valueOf(f.get("fixed_version")).isBlank()) {
                throw new IllegalArgumentException("漏洞 " + f.get("cve_id") + " 无修复版本信息，需人工处理");
            }
            Map<String, Object> target = new LinkedHashMap<>(Map.of(
                    "agent_id", agentId,
                    "os_type", f.get("os_type"),
                    "os_version", f.get("os_version") == null ? "" : f.get("os_version"),
                    "pkg_name", f.get("software"),
                    "target_version", f.get("fixed_version"),
                    "cve_id", f.get("cve_id"),
                    "finding_id", fid));
            var identity = currentPackageIdentity(agentId, String.valueOf(f.get("software")), String.valueOf(f.get("installed_version")));
            verifyFindingIdentity(f, identity);
            verifyFindingEvidence(f);
            if (com.alinksec.service.scan.PackageVersions.compare(String.valueOf(identity.get("source")),
                    String.valueOf(f.get("fixed_version")), String.valueOf(f.get("installed_version"))) <= 0) {
                throw new IllegalArgumentException("修复目标必须是更高的完整原生版本，同版本重装或降级请人工处理");
            }
            target.put("inventory", identity);
            target.put("rule_source_id", f.get("rule_source_id"));
            target.put("rule_digest", f.get("rule_digest"));
            resolveTargets.add(target);
        }
        PatchRepoService.Resolved resolved = patchRepo.resolveForAgents(resolveTargets);
        if (!resolved.missing().isEmpty()) {
            // 补丁仓库未覆盖 → 阻断创建，返回缺失清单（docs/05：禁止执行未覆盖安装）
            throw new IllegalArgumentException("以下补丁未导入仓库，已阻断创建：\n" + String.join("\n", resolved.missing()));
        }

        // 构造下发内容（refId = finding id，结果上报据此回写漏洞状态）
        Map<String, List<FixItem>> byAgent = new LinkedHashMap<>();
        List<Map<String, Object>> targetRows = new ArrayList<>();
        for (Map<String, Object> t : resolveTargets) {
            Map<String, Object> patch = resolved.hits().get(t.get("agent_id") + ":" + t.get("finding_id"));
            String source = String.valueOf(((Map<?, ?>) t.get("inventory")).get("source"));
            String expectedType = switch (source) { case "rpm" -> "rpm"; case "dpkg" -> "deb"; default -> "msu"; };
            if (!expectedType.equals(patch.get("repo_type"))) {
                throw new IllegalArgumentException("补丁类型与当前软件包来源不一致: " + t.get("pkg_name"));
            }
            Map<String, Object> payload = new LinkedHashMap<>(Map.of(
                    "repo_type", patch.get("repo_type"),
                    "pkg_name", t.get("pkg_name"),
                    "target_version", t.get("target_version"),
                    "download_url", "",
                    "sha256", patch.get("sha256"),
                    "cve_id", t.get("cve_id"),
                    "finding_id", String.valueOf(t.get("finding_id"))));
            payload.put("inventory", t.get("inventory"));
            payload.put("patch_review", patchRepo.pin(patch, t));
            payload.put("rule_source_id", t.get("rule_source_id"));
            payload.put("rule_digest", t.get("rule_digest"));
            byAgent.computeIfAbsent(String.valueOf(t.get("agent_id")), k -> new ArrayList<>())
                    .add(FixItem.newBuilder()
                            .setRefId(String.valueOf(t.get("finding_id")))
                            .setType(FixItem.FixType.PACKAGE)
                            .setPayload(JsonUtils.write(payload))
                            .build());
            targetRows.add(Map.of("ref_type", "vuln_finding",
                    "ref_id", String.valueOf(t.get("finding_id")),
                    "agent_id", t.get("agent_id"),
                    "fix_payload", JsonUtils.write(payload)));
        }

        String taskNo = "FP" + LocalDateTime.now().format(NO_FMT)
                + java.util.UUID.randomUUID().toString().replace("-","").substring(0,12);
        long taskId = jdbc.queryForObject(
                "INSERT INTO t_fix_task (task_no, name, type, scope, targets, status, created_by, approver, "
                        + "approver_id,approved, window_start, window_end) "
                        + "VALUES (?, ?, 2, ?, ?, 0, ?, ?, ?,false, ?, ?) RETURNING id",
                Long.class, taskNo,
                name == null || name.isBlank() ? taskNo + " 软件包修复" : name,
                JsonUtils.write(Map.of("agent_ids", List.copyOf(byAgent.keySet()))),
                JsonUtils.write(targetRows), createdBy, approver,approverId,database.timestamp(ws), database.timestamp(we));

        // 预写 t_fix_record（待执行/待审批派发）
        for (Map<String, Object> row : targetRows) {
            jdbc.update("""
                    INSERT INTO t_fix_record (task_id, agent_id, ref_id, ref_type)
                    VALUES (?, ?, ?, 'vuln_finding')
                    """, taskId, row.get("agent_id"), row.get("ref_id"));
        }
        log.info("软件包修复任务已创建（待审批）: task_id={} task_no={} approver={} items={}",
                taskId, taskNo, approver, targetRows.size());
        return Map.of("taskId", taskId, "taskNo", taskNo, "pendingApprove", true);
    }

    /** Only the designated, currently enabled account may approve; request labels are never identities. */
    @Transactional
    public Map<String,Object> approve(long taskId,Long actor) {
        return transaction.execute(status -> {
            String username=requireActor(actor);
            var task=lockedTask(taskId);
            if (((Number)task.get("type")).intValue()!=2) throw new IllegalArgumentException("仅软件包类任务需审批");
            if (!(task.get("approver_id") instanceof Number designated) || designated.longValue()!=actor.longValue())
                throw new IllegalArgumentException("当前登录账号不是该任务指定的审批人；旧任务缺少账号绑定时请重新创建");
            if (((Number)task.get("status")).intValue()>1) throw new IllegalArgumentException("任务已结束，不能再次审批");
            if (expired(task)) throw new IllegalArgumentException("维护窗口已结束，不能审批或派发");
            if (isTrue(task.get("approved"))) return Map.of("taskId",taskId,"state","already");
            int changed=jdbc.update("UPDATE t_fix_task SET approved=true,approved_at=CURRENT_TIMESTAMP,approved_by=? WHERE id=? AND status=0 AND approved=false",actor,taskId);
            if (changed!=1) throw new IllegalArgumentException("任务状态已变化，请刷新后重试");
            log.info("软件包任务审批: task={} uid={} username={}",taskId,actor,username);
            boolean dispatched=dispatchApproved(taskId);
            return Map.of("taskId",taskId,"state",dispatched ? "dispatched" : "waiting_window");
        });
    }

    public List<Map<String,Object>> approvers() {
        return jdbc.queryForList("SELECT u.id,u.username,u.real_name FROM t_user u JOIN t_role r ON r.id=u.role_id WHERE u.status=1 AND r.name IN ('admin','operator') ORDER BY u.username");
    }

    private String requireActor(Long uid) {
        if (uid==null || uid<=0) throw new IllegalArgumentException("需要已验证的登录身份");
        var rows=jdbc.queryForList("SELECT u.username FROM t_user u JOIN t_role r ON r.id=u.role_id WHERE u.id=? AND u.status=1 AND r.name IN ('admin','operator')",uid);
        if (rows.size()!=1) throw new IllegalArgumentException("账号已禁用或没有修复操作权限");
        return String.valueOf(rows.get(0).get("username"));
    }

    private Map<String,Object> lockedTask(long taskId) {
        if (jdbc.update("UPDATE t_fix_task SET status=status WHERE id=?",taskId)!=1) throw new IllegalArgumentException("修复任务不存在");
        return jdbc.queryForMap("SELECT id,type,status,approved,approver_id,approved_by,created_by,window_start,window_end,started_at,dispatched_at,CAST(targets AS TEXT) AS targets FROM t_fix_task WHERE id=?",taskId);
    }
    private boolean expired(Map<String,Object> task) {
        return task.get("window_end")!=null && !OffsetDateTime.now().isBefore(database.readOffsetDateTime(task.get("window_end")));
    }

    /** Each scheduler attempt has its own transaction, including the conditional claim and durable commands. */
    @Scheduled(fixedDelay=60_000,initialDelay=60_000)
    public void dispatchWindowReached() {
        Object now=database.timestamp(java.time.Instant.now());
        var ids=jdbc.queryForList("SELECT id FROM t_fix_task WHERE type=2 AND status=0 AND ((approved=true AND (window_start IS NULL OR window_start<=?)) OR window_end<=?) ORDER BY id LIMIT 100",Long.class,now,now);
        for (Long id:ids) {
            try {
                transaction.executeWithoutResult(status -> {
                    var task=lockedTask(id);
                    if (((Number)task.get("status")).intValue()!=0) return;
                    if (expired(task)) { stopTask(id,3,"维护窗口已结束，未派发的任务已停止",null); return; }
                    if (isTrue(task.get("approved"))) dispatchApproved(id);
                });
            } catch (IllegalArgumentException e) {
                transaction.executeWithoutResult(status -> {
                    var task=lockedTask(id);
                    if (((Number)task.get("status")).intValue()==0) stopTask(id,3,e.getMessage(),null);
                });
                log.warn("软件包任务停止派发: task={} reason={}",id,e.getMessage());
            } catch (RuntimeException e) { log.error("窗口派发暂时失败，保留任务等待重试: task={}",id,e); }
        }
    }

    private boolean dispatchApproved(long taskId) {
        var task=lockedTask(taskId);
        if (((Number)task.get("status")).intValue()!=0 || !isTrue(task.get("approved"))) return false;
        requireActor(task.get("approved_by") instanceof Number n ? n.longValue() : null);
        if (!java.util.Objects.equals(task.get("approver_id"),task.get("approved_by"))) throw new IllegalArgumentException("审批账号绑定无效，请重新创建任务");
        if (expired(task)) throw new IllegalArgumentException("维护窗口已结束");
        if (task.get("window_start")!=null && OffsetDateTime.now().isBefore(database.readOffsetDateTime(task.get("window_start")))) return false;
        if (jdbc.update("UPDATE t_fix_task SET status=1,started_at=CURRENT_TIMESTAMP,dispatched_at=CURRENT_TIMESTAMP WHERE id=? AND type=2 AND status=0 AND approved=true AND dispatched_at IS NULL",taskId)!=1) return false;
        List<Map<String,Object>> targets=JsonUtils.read(String.valueOf(task.get("targets")),List.class);
        Map<String,List<FixItem>> byAgent=new LinkedHashMap<>();
        targets.stream().map(t -> String.valueOf(t.get("agent_id"))).distinct().sorted().forEach(agent -> jdbc.update("UPDATE t_agent SET software_revision=software_revision WHERE agent_id=? AND deleted=false",agent));
        for (var target:targets) {
            boolean windows="windows_update".equals(target.get("ref_type"));
            var payload=windows ? new WindowsUpdateValidation(jdbc,database).validate(target) : validation.validate(target);
            payload.remove("validated_patch");
            if(!windows) payload.put("download_url",""); // Issued after commit, just before the actual delivery attempt.
            byAgent.computeIfAbsent(String.valueOf(target.get("agent_id")),ignored -> new ArrayList<>()).add(FixItem.newBuilder().setRefId(String.valueOf(target.get("ref_id"))).setType(windows?FixItem.FixType.WINDOWS_UPDATE:FixItem.FixType.PACKAGE).setPayload(JsonUtils.write(payload)).build());
        }
        if (byAgent.isEmpty()) throw new IllegalArgumentException("软件包任务没有有效目标");
        for (var entry:byAgent.entrySet()) {
            String cmdId=commandService.dispatchAfterCommit(entry.getKey(),Command.newBuilder().setVulnFix(CmdVulnFix.newBuilder().setTaskId(String.valueOf(taskId)).addAllFixes(entry.getValue())),((Number)task.get("approved_by")).longValue());
            jdbc.update("UPDATE t_fix_record SET command_id=? WHERE task_id=? AND agent_id=? AND status=0",cmdId,taskId,entry.getKey());
        }
        log.info("软件包任务已持久排队，提交后派发: task={} agents={}",taskId,byAgent.size());
        return true;
    }

    @Transactional
    public Map<String,Object> cancel(long taskId,Long actor,String reason) {
        return transaction.execute(status -> {
            requireActor(actor);
            if (reason==null || reason.trim().length()<2 || reason.length()>1024) throw new IllegalArgumentException("取消原因需为 2 至 1024 字");
            var task=lockedTask(taskId);
            if (((Number)task.get("type")).intValue()!=2 || ((Number)task.get("status")).intValue()>1) throw new IllegalArgumentException("只能取消尚未开始安装的软件包任务");
            if (!matchesId(task.get("created_by"),actor) && !matchesId(task.get("approver_id"),actor)) throw new IllegalArgumentException("只有创建人或指定审批人可取消该任务");
            Integer delivered=jdbc.queryForObject("SELECT count(*) FROM t_fix_record r JOIN t_command c ON c.cmd_id=r.command_id WHERE r.task_id=? AND c.status<>0",Integer.class,taskId);
            if (delivered!=null && delivered>0) throw new IllegalArgumentException("任务指令已经送出，不能取消或承诺回滚，请查看执行结果并人工处理");
            stopTask(taskId,4,"取消："+reason.trim(),actor);
            return Map.of("taskId",taskId,"state","cancelled");
        });
    }

    private void stopTask(long taskId,int state,String reason,Long actor) {
        String bounded=reason==null ? "修复任务停止" : reason.substring(0,Math.min(2048,reason.length()));
        jdbc.update("UPDATE t_fix_task SET status=?,failure_reason=?,cancelled_by=?,finished_at=CURRENT_TIMESTAMP WHERE id=? AND status IN (0,1)",state,bounded,actor,taskId);
        jdbc.update("UPDATE t_command SET status=5,finished_at=CURRENT_TIMESTAMP,result=? WHERE status IN (0,1,2,3) AND cmd_id IN (SELECT command_id FROM t_fix_record WHERE task_id=?)",JsonUtils.write(Map.of("reason",bounded)),taskId);
        jdbc.update("UPDATE t_fix_record SET status=5,log=?,finished_at=CURRENT_TIMESTAMP WHERE task_id=? AND status=0",bounded,taskId);
        jdbc.update("DELETE FROM t_agent_download_token WHERE fix_task_id=?",taskId);
    }

    private void verifyFindingEvidence(Map<String,Object> finding) { validation.evidence(finding); }
    private Map<String,Object> currentPackageIdentity(String agent,String name,String version) { return validation.identity(agent,name,version); }
    private static void verifyFindingIdentity(Map<String,Object> finding,Map<?,?> identity) { PackageRepairValidation.findingIdentity(finding,identity); }

    private static OffsetDateTime parseTime(String s) {
        if (s == null || s.isBlank()) {
            return null;
        }
        try { return OffsetDateTime.parse(s); }
        catch (java.time.format.DateTimeParseException e) {
            try { return LocalDateTime.parse(s).atZone(java.time.ZoneId.of("Asia/Shanghai")).toOffsetDateTime(); }
            catch (java.time.format.DateTimeParseException invalid) { throw new IllegalArgumentException("维护窗口时间格式非法，请使用 ISO 日期时间"); }
        }
    }

    private static boolean isTrue(Object value) {
        return value instanceof Boolean bool ? bool
                : value instanceof Number number && number.intValue() != 0;
    }
    private static boolean matchesId(Object value,Long id) { return id!=null && value instanceof Number n && n.longValue()==id.longValue(); }
}
