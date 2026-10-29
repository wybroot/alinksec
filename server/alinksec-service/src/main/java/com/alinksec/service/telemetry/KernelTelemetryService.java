package com.alinksec.service.telemetry;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.RptSecurityEvent;
import com.alinksec.service.alert.SecurityEventService;
import com.alinksec.service.config.AlinkSecProperties;
import com.fasterxml.jackson.databind.JsonNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * 内核与 eBPF 遥测接入服务（docs/84 第六批 F01-kernel ~ F04-kernel）。
 * 接收来自外部 Falco HTTP 输出或 Elkeid Driver/Agent 上报的内核遥测事件，
 * 解析并富化 pid_tree、container context、MITRE tags，无缝转发至 SecurityEventService。
 * 同时记录遥测探针健康心跳，未启用时不产生异常告警。
 */
@Service
public class KernelTelemetryService {

    private static final Logger log = LoggerFactory.getLogger(KernelTelemetryService.class);

    private final SecurityEventService securityEventService;
    private final AlinkSecProperties properties;
    private final JdbcTemplate jdbc;

    // 内存探针心跳注册表: source -> ProbeStatus
    private final Map<String, ProbeStatus> probeRegistry = new java.util.concurrent.ConcurrentHashMap<>();

    public static class ProbeStatus {
        public String source;
        public long lastSeenMs;
        public long eventCount;
        public String lastEvent;

        public ProbeStatus(String source) {
            this.source = source;
            this.lastSeenMs = System.currentTimeMillis();
        }
    }

    public KernelTelemetryService(SecurityEventService securityEventService,
                                  AlinkSecProperties properties,
                                  JdbcTemplate jdbc) {
        this.securityEventService = securityEventService;
        this.properties = properties;
        this.jdbc = jdbc;
    }

    /**
     * 接收并解析 Falco JSON Webhook 告警 (F01-kernel)。
     * Falco 标准格式字段：time, rule, priority, output, output_fields (包含 proc.cmdline, proc.pid, container.id 等)
     */
    public boolean ingestFalcoEvent(String payload) {
        try {
            JsonNode root = JsonUtils.read(payload);
            if (root.isEmpty() || !root.has("rule")) {
                log.warn("无效的 Falco 事件数据包: 缺少 rule 字段");
                return false;
            }

            recordHeartbeat("falco", root.path("rule").asText());

            String ruleName = root.path("rule").asText("falco-rule");
            String priority = root.path("priority").asText("Notice").toUpperCase();
            String output = root.path("output").asText("");
            JsonNode fields = root.path("output_fields");

            // 映射 Falco 优先级至 ALinkSec severity: 1(low), 2(medium), 3(high), 4(critical)
            int severity = mapFalcoPriority(priority);

            // 提取关键字段
            String agentId = "falco-node";
            if (fields.has("k8s.pod.name")) {
                agentId = fields.path("k8s.pod.name").asText();
            } else if (fields.has("container.name")) {
                agentId = fields.path("container.name").asText();
            }

            // 关联主机 agent_id（如果有 hostname）
            if (fields.has("nodename")) {
                String nodename = fields.path("nodename").asText();
                String hostAgent = resolveAgentIdByHost(nodename);
                if (hostAgent != null) {
                    agentId = hostAgent;
                }
            }

            Map<String, Object> detail = new LinkedHashMap<>();
            detail.put("telemetry_source", "falco_ebpf");
            detail.put("falco_rule", ruleName);
            detail.put("falco_priority", priority);
            detail.put("raw_output", output);

            // 提取容器上下文
            if (fields.has("container.id") || fields.has("container.name")) {
                Map<String, Object> containerCtx = new LinkedHashMap<>();
                containerCtx.put("id", fields.path("container.id").asText(""));
                containerCtx.put("name", fields.path("container.name").asText(""));
                containerCtx.put("image", fields.path("container.image.repository").asText(""));
                detail.put("container", containerCtx);
                detail.put("in_container", true);
                detail.put("container_id", fields.path("container.id").asText(""));
            } else {
                detail.put("in_container", false);
            }

            // 提取进程与 PID
            if (fields.has("proc.pid")) {
                detail.put("proc_pid", fields.path("proc.pid").asInt());
            }
            if (fields.has("proc.cmdline")) {
                detail.put("proc_cmdline", fields.path("proc.cmdline").asText());
            }
            if (fields.has("proc.name")) {
                detail.put("proc_name", fields.path("proc.name").asText());
            }

            // MITRE ATT&CK 标签提取
            JsonNode tags = root.path("tags");
            if (tags.isArray()) {
                List<String> tagList = new ArrayList<>();
                tags.forEach(t -> tagList.add(t.asText()));
                detail.put("tags", tagList);
            }

            // 构建统一 RptSecurityEvent
            RptSecurityEvent event = RptSecurityEvent.newBuilder()
                    .setType("process")
                    .setRuleId("falco-" + ruleName.toLowerCase().replaceAll("[^a-z0-9_-]", "-"))
                    .setRuleName("Falco: " + ruleName)
                    .setSeverityValue(severity)
                    .setActionTaken("alert_only")
                    .setDetail(JsonUtils.write(detail))
                    .build();

            securityEventService.onEvent(agentId, event);
            return true;
        } catch (Exception e) {
            log.error("Falco 遥测事件解析入库异常", e);
            return false;
        }
    }

    /**
     * 接收并解析 Elkeid Driver 内核事件 (F02-kernel)。
     * Elkeid Driver 数据包结构：data_type, exe, pid, ppid, nodename, pid_tree, etc.
     */
    public boolean ingestElkeidEvent(String payload) {
        try {
            JsonNode root = JsonUtils.read(payload);
            if (root.isEmpty() || !root.has("data_type")) {
                log.warn("无效的 Elkeid 事件数据包: 缺少 data_type 字段");
                return false;
            }

            int dataType = root.path("data_type").asInt(0);
            recordHeartbeat("elkeid", "type_" + dataType);

            String nodename = root.path("nodename").asText("elkeid-node");
            String agentId = resolveAgentIdByHost(nodename);
            if (agentId == null) {
                agentId = nodename;
            }

            String exe = root.path("exe").asText("");
            int pid = root.path("pid").asInt(0);
            String pidTree = root.path("pid_tree").asText("");

            String type = "process";
            String ruleId = "elkeid-hook-" + dataType;
            String ruleName = "Elkeid Driver Event " + dataType;
            int severity = 2; // medium default

            // 针对核心 hook 分类处理
            switch (dataType) {
                case 59 -> { // execve
                    ruleName = "Elkeid: Process Execve";
                    severity = 1; // low baseline telemetry
                }
                case 604 -> { // update_cred 提权 (uid 0)
                    ruleName = "Elkeid: Privilege Escalation (update_cred)";
                    severity = 4; // critical
                }
                case 611 -> { // privilege_escalation
                    ruleName = "Elkeid: Privilege Escalation Detected";
                    severity = 4; // critical
                }
                case 356 -> { // memfd_create (无文件攻击)
                    ruleName = "Elkeid: Memory File Created (memfd_create)";
                    severity = 3; // high
                }
                case 603 -> { // load_module (内核模块加载)
                    ruleName = "Elkeid: Kernel Module Loaded";
                    severity = 3; // high
                }
                case 700, 701, 702, 703 -> { // Rootkit 检测 (proc/syscall/module hook)
                    ruleName = "Elkeid: Kernel Rootkit Tampering Detected";
                    severity = 4; // critical
                }
            }

            Map<String, Object> detail = new LinkedHashMap<>();
            detail.put("telemetry_source", "elkeid_driver");
            detail.put("data_type", dataType);
            detail.put("exe", exe);
            detail.put("pid", pid);
            detail.put("ppid", root.path("ppid").asInt(0));
            detail.put("uid", root.path("uid").asInt(-1));
            detail.put("nodename", nodename);
            if (!pidTree.isBlank()) {
                detail.put("pid_tree", pidTree);
            }
            if (root.has("argv")) {
                detail.put("argv", root.path("argv").asText());
            }

            RptSecurityEvent event = RptSecurityEvent.newBuilder()
                    .setType(type)
                    .setRuleId(ruleId)
                    .setRuleName(ruleName)
                    .setSeverityValue(severity)
                    .setActionTaken("alert_only")
                    .setDetail(JsonUtils.write(detail))
                    .build();

            securityEventService.onEvent(agentId, event);
            return true;
        } catch (Exception e) {
            log.error("Elkeid 遥测事件解析入库异常", e);
            return false;
        }
    }

    /**
     * 获取内核遥测探针健康状态 (F04-kernel)。
     * 如果未配置启用，则返回 disabled 状态，绝不伪报 down/异常。
     */
    public Map<String, Object> getTelemetryHealth() {
        boolean enabled = properties.getTelemetry().isEnabled();
        if (!enabled) {
            return Map.of(
                    "status", "disabled",
                    "message", "内核/eBPF 遥测未启用；Agent 采用内置轻量级安全轮询机制",
                    "probes", Collections.emptyMap()
            );
        }

        long now = System.currentTimeMillis();
        Map<String, Object> probeDetails = new LinkedHashMap<>();
        for (Map.Entry<String, ProbeStatus> entry : probeRegistry.entrySet()) {
            ProbeStatus p = entry.getValue();
            boolean active = (now - p.lastSeenMs) < 60_000; // 60s 内有事件视为活跃
            probeDetails.put(entry.getKey(), Map.of(
                    "active", active,
                    "lastSeenSecondsAgo", (now - p.lastSeenMs) / 1000,
                    "eventCount", p.eventCount,
                    "lastEvent", p.lastEvent != null ? p.lastEvent : ""
            ));
        }

        return Map.of(
                "status", "healthy",
                "message", "内核/eBPF 遥测接入层运行中",
                "probes", probeDetails
        );
    }

    private void recordHeartbeat(String source, String eventType) {
        probeRegistry.compute(source, (k, v) -> {
            if (v == null) v = new ProbeStatus(source);
            v.lastSeenMs = System.currentTimeMillis();
            v.eventCount++;
            v.lastEvent = eventType;
            return v;
        });
    }

    private String resolveAgentIdByHost(String hostOrIp) {
        if (hostOrIp == null || hostOrIp.isBlank()) return null;
        try {
            List<String> list = jdbc.queryForList(
                    "SELECT agent_id FROM t_agent WHERE hostname = ? OR ip = ? LIMIT 1",
                    String.class, hostOrIp, hostOrIp);
            return list.isEmpty() ? null : list.get(0);
        } catch (Exception e) {
            return null;
        }
    }

    private int mapFalcoPriority(String priority) {
        return switch (priority.toUpperCase()) {
            case "EMERGENCY", "ALERT", "CRITICAL" -> 4; // critical
            case "ERROR", "WARNING" -> 3; // high
            case "NOTICE" -> 2; // medium
            default -> 1; // low / info
        };
    }
}
