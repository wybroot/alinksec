package com.alinksec.common.error;

/**
 * 平台统一错误码（对齐通信协议文档 §7；M2 REST 层直接复用）。
 * 区间：1xxxx 通用 / 2xxxx 注册与通道 / 3xxxx 业务。
 */
public enum ErrorCode {

    OK(0, "成功"),

    // 1xxxx 通用
    INTERNAL_ERROR(10000, "服务内部错误"),
    INVALID_ARGUMENT(10001, "参数错误"),

    // 2xxxx 注册与通道
    ENROLL_TOKEN_INVALID(20001, "注册码无效或已过期"),
    ENROLL_TOKEN_EXHAUSTED(20002, "注册码使用次数已用尽"),
    MACHINE_ALREADY_ENROLLED(20003, "该主机已注册（machine_id 重复）"),
    CERT_INVALID(20004, "客户端证书无效或已过期"),
    CERT_AGENT_MISMATCH(20005, "证书与 agent_id 不匹配"),
    AGENT_DISABLED(20006, "Agent 已被禁用"),
    AGENT_NOT_FOUND(20007, "Agent 不存在"),
    AGENT_OFFLINE(20008, "Agent 不在线"),

    // 3xxxx 业务
    COMMAND_NOT_FOUND(30001, "指令不存在"),
    POLICY_NOT_FOUND(30002, "策略不存在");

    private final int code;
    private final String message;

    ErrorCode(int code, String message) {
        this.code = code;
        this.message = message;
    }

    public int code() { return code; }

    public String message() { return message; }
}
