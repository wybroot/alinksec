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

            // 提取关键字段并解析主机归属 (R71)
            String candidateHost = null;
            if (fields.hasNonNull("nodename") && !fields.path("nodename").asText().isBlank()) {
                candidateHost = fields.path("nodename").asText();
            } else if (fields.hasNonNull("evt.hostname") && !fields.path("evt.hostname").asText().isBlank()) {
                candidateHost = fields.path("evt.hostname").asText();
            } else if (root.hasNonNull("hostname") && !root.path("hostname").asText().isBlank()) {
                candidateHost = root.path("hostname").asText();
            }

            String agentId;
            boolean hostBound = false;
            String hostAgent = resolveAgentIdByHost(candidateHost);
            if (hostAgent != null) {
                agentId = hostAgent;
                hostBound = true;
            } else {
                // 未绑定平台登记主机：使用未绑定标识，严禁直接使用 Pod 或容器名称冒充 agentId
                agentId = "unbound-" + (candidateHost != null ? candidateHost : "unknown");
            }

            Map<String, Object> detail = new LinkedHashMap<>();
            detail.put("telemetry_source", "falco_ebpf");
            detail.put("falco_rule", ruleName);
            detail.put("falco_priority", priority);
            detail.put("raw_output", redactSensitive(output));
            detail.put("host_bound", hostBound);
            if (candidateHost != null) {
                detail.put("nodename", candidateHost);
            }
            if (!hostBound) {
                detail.put("unbound_host", candidateHost != null ? candidateHost : "unknown");
                detail.put("response_skipped", true); // 禁止对未绑定主机触发处置响应
            }

            // 提取容器上下文（R74: host / container / unknown 三态处理）
            String containerId = fields.path("container.id").asText("");
            String containerName = fields.path("container.name").asText("");
            String containerStatus;
            boolean inContainer;

            if ("host".equalsIgnoreCase(containerId) || "host".equalsIgnoreCase(containerName)) {
                containerStatus = "host";
                inContainer = false;
            } else if (!containerId.isBlank() && !"none".equalsIgnoreCase(containerId)) {
                containerStatus = "container";
                inContainer = true;
            } else if (!containerName.isBlank() && !"none".equalsIgnoreCase(containerName)) {
                containerStatus = "container";
                inContainer = true;
            } else if (!fields.has("container.id") && !fields.has("container.name")) {
                containerStatus = "unknown";
                inContainer = false;
            } else {
                containerStatus = "host";
                inContainer = false;
            }

            detail.put("container_status", containerStatus);
            detail.put("in_container", inContainer);
            if (inContainer) {
                Map<String, Object> containerCtx = new LinkedHashMap<>();
                containerCtx.put("id", containerId);
                containerCtx.put("name", containerName);
                containerCtx.put("image", fields.path("container.image.repository").asText(""));
                detail.put("container", containerCtx);
                detail.put("container_id", containerId);
            }

            // 提取进程与 PID
            if (fields.has("proc.pid")) {
                int pid = fields.path("proc.pid").asInt();
                detail.put("proc_pid", pid);
                String pName = fields.path("proc.name").asText("proc");
                detail.put("process_key", agentId + ":" + pid + ":" + pName);
            }
            if (fields.has("proc.cmdline")) {
                detail.put("proc_cmdline", redactSensitive(fields.path("proc.cmdline").asText()));
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
            String hostAgent = resolveAgentIdByHost(nodename);
            String agentId;
            boolean hostBound = false;
            if (hostAgent != null) {
                agentId = hostAgent;
                hostBound = true;
            } else {
                agentId = "unbound-" + nodename;
            }

            String exe = root.path("exe").asText("");
            int pid = root.path("pid").asInt(0);
            String pidTree = root.path("pid_tree").asText("");

            String type = "process";
            String ruleId = "elkeid-hook-" + dataType;
            String ruleName = "Elkeid Driver Event " + dataType;
            int severity = 2; // medium default
            String actionTaken = "alert_only";

            Map<String, Object> detail = new LinkedHashMap<>();
            detail.put("telemetry_source", "elkeid_driver");
            detail.put("data_type", dataType);
            detail.put("nodename", nodename);
            detail.put("host_bound", hostBound);
            if (!hostBound) {
                detail.put("unbound_host", nodename);
                detail.put("response_skipped", true);
            }

            // 提取容器上下文（R74）
            String containerId = root.path("container_id").asText("");
            if (containerId.isBlank()) containerId = root.path("docker_id").asText("");
            String podName = root.path("pod_name").asText("");
            boolean inContainer = false;
            String containerStatus = "unknown";
            if (!containerId.isBlank() || !podName.isBlank()) {
                containerStatus = "container";
                inContainer = true;
                detail.put("container_id", containerId);
                if (!podName.isBlank()) detail.put("pod_name", podName);
            } else if (root.has("container_id") || root.has("pod_name")) {
                containerStatus = "host";
            }
            detail.put("container_status", containerStatus);
            detail.put("in_container", inContainer);

            // 针对核心 hook 分类处理与字段保全 (R72 / R75)
            switch (dataType) {
                case 42 -> { // connect
                    type = "network";
                    ruleId = "elkeid-hook-connect";
                    ruleName = "Elkeid: Network Connect (Telemetry)";
                    severity = 1; // info (日常遥测，不盲目作为高危告警)
                    actionTaken = "telemetry_only";
                    detail.put("telemetry_only", true);
                    detail.put("response_skipped", true);
                    detail.put("sip", root.path("sip").asText(""));
                    detail.put("sport", root.path("sport").asInt(0));
                    detail.put("dip", root.path("dip").asText(""));
                    detail.put("dport", root.path("dport").asInt(0));
                    detail.put("sa_family", root.path("sa_family").asInt(0));
                    detail.put("socket_type", root.path("socket_type").asInt(0));
                    detail.put("res", root.path("res").asInt(0));
                    detail.put("source_ip", root.path("dip").asText(""));
                }
                case 59 -> { // execve
                    type = "process";
                    ruleId = "elkeid-hook-execve";
                    ruleName = "Elkeid: Process Execve (Telemetry)";
                    severity = 1; // info (日常遥测，不盲目作为高危告警)
                    actionTaken = "telemetry_only";
                    detail.put("telemetry_only", true);
                    detail.put("response_skipped", true);
                }
                case 601 -> { // dns_query
                    type = "dns";
                    ruleId = "elkeid-hook-dns";
                    ruleName = "Elkeid: DNS Query";
                    severity = 2; // low
                    detail.put("query", root.path("query").asText(""));
                    detail.put("dns_ip", root.path("dns_ip").asText(""));
                    detail.put("res", root.path("res").asInt(0));
                }
                case 602 -> { // file
                    type = "file";
                    ruleId = "elkeid-hook-file";
                    ruleName = "Elkeid: File Operation";
                    severity = 2; // low
                    detail.put("file_path", root.path("file_path").asText(""));
                    detail.put("flags", root.path("flags").asInt(0));
                    detail.put("mode", root.path("mode").asInt(0));
                    detail.put("res", root.path("res").asInt(0));
                }
                case 604 -> { // update_cred 提权 (uid 0)
                    ruleName = "Elkeid: Privilege Escalation (update_cred)";
                    severity = 5; // critical
                    detail.put("old_uid", root.path("old_uid").asInt(-1));
                    detail.put("new_uid", root.path("new_uid").asInt(-1));
                    detail.put("res", root.path("res").asInt(0));
                }
                case 611 -> { // privilege_escalation
                    ruleName = "Elkeid: Privilege Escalation Detected";
                    severity = 5; // critical
                }
                case 356 -> { // memfd_create (无文件攻击)
                    ruleName = "Elkeid: Memory File Created (memfd_create)";
                    severity = 4; // high
                    detail.put("fd_name", root.path("name").asText(""));
                    detail.put("flags", root.path("flags").asInt(0));
                    detail.put("res", root.path("res").asInt(0));
                }
                case 603 -> { // load_module (内核模块加载)
                    ruleName = "Elkeid: Kernel Module Loaded";
                    severity = 4; // high
                    detail.put("ko_file", root.path("ko_file").asText(""));
                    detail.put("res", root.path("res").asInt(0));
                }
                case 700, 701, 702, 703 -> { // Rootkit 检测 (proc/syscall/module hook)
                    ruleName = "Elkeid: Kernel Rootkit Tampering Detected (" + dataType + ")";
                    severity = 5; // critical
                }
            }

            detail.put("exe", exe);
            detail.put("pid", pid);
            if (pid > 0) {
                detail.put("process_key", agentId + ":" + pid + ":" + (exe.isBlank() ? "proc" : exe));
            }
            detail.put("ppid", root.path("ppid").asInt(0));
            detail.put("uid", root.path("uid").asInt(-1));
            if (!pidTree.isBlank()) {
                detail.put("pid_tree", pidTree);
            }
            if (root.has("argv")) {
                detail.put("argv", redactSensitive(root.path("argv").asText()));
            }

            RptSecurityEvent event = RptSecurityEvent.newBuilder()
                    .setType(type)
                    .setRuleId(ruleId)
                    .setRuleName(ruleName)
                    .setSeverityValue(severity)
                    .setActionTaken(actionTaken)
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

    public static String redactSensitive(String text) {
        if (text == null || text.isBlank()) return text;
        return text.replaceAll("(?i)(--?(?:password|passwd|pwd|token|secret|api[-_]?key|access[-_]?key|client[-_]?secret|auth|private[-_]?key|credentials?)\\s*[=:]\\s*)[^\\s,;\"']+", "$1***")
                   .replaceAll("(?i)(Bearer\\s+)[A-Za-z0-9._~+/-]+", "$1***");
    }

    private int mapFalcoPriority(String priority) {
        return switch (priority.toUpperCase()) {
            case "EMERGENCY", "ALERT", "CRITICAL" -> 5; // critical (Severity.SEV_CRITICAL = 5)
            case "ERROR", "WARNING" -> 4; // high (Severity.SEV_HIGH = 4)
            case "NOTICE" -> 3; // medium (Severity.SEV_MEDIUM = 3)
            case "INFORMATIONAL", "INFO" -> 2; // low (Severity.SEV_LOW = 2)
            default -> 1; // info (Severity.SEV_INFO = 1)
        };
    }
}
