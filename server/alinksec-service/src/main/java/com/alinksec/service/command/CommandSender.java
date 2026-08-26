package com.alinksec.service.command;

import com.alinksec.proto.Command;

/**
 * 指令下发通道（由 gateway 的在线连接注册表实现，避免 service→gateway 反向依赖）。
 */
public interface CommandSender {

    /**
     * 向在线 Agent 的 stream 写入指令。
     *
     * @return false = Agent 不在线或写入失败
     */
    boolean send(String agentId, Command command);
}
