package com.alinksec.service.agent;

import java.time.OffsetDateTime;

/**
 * t_agent 行映射（M1 用到的列）。
 */
public record AgentEntity(
        Long id,
        String agentId,
        String hostname,
        String ip,
        short osType,
        String osVersion,
        String kernel,
        String arch,
        String agentVersion,
        String machineId,
        Long groupId,
        short status,          // 0待激活 1在线 2离线 3禁用 4已删除
        boolean protectEnabled,
        String policyVersion,
        String certSerial,
        OffsetDateTime lastHeartbeat,
        OffsetDateTime createdAt,
        OffsetDateTime updatedAt) {

    public static final short STATUS_PENDING = 0;
    public static final short STATUS_ONLINE = 1;
    public static final short STATUS_OFFLINE = 2;
    public static final short STATUS_DISABLED = 3;
    public static final short STATUS_DELETED = 4;
}
