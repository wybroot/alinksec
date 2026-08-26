package com.alinksec.gateway.channel;

import com.alinksec.proto.Command;
import io.grpc.stub.StreamObserver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Agent 在线连接注册表：agent_id → 下行 stream。
 * 实现 CommandSender：离线返回 false（指令保持 PENDING）。
 * 同一 agent 重复建流时踢旧连接（网络抖动快速重连场景）。
 */
@Component
public class ConnectionRegistry implements com.alinksec.service.command.CommandSender {

    private static final Logger log = LoggerFactory.getLogger(ConnectionRegistry.class);

    private final Map<String, StreamObserver<Command>> streams = new ConcurrentHashMap<>();

    public void register(String agentId, StreamObserver<Command> stream) {
        StreamObserver<Command> old = streams.put(agentId, stream);
        if (old != null) {
            log.info("重复建流，踢掉旧连接: agent={}", agentId);
            try {
                old.onCompleted();
            } catch (Exception ignored) {
            }
        }
        log.info("Agent 上线: agent={} online={}", agentId, streams.size());
    }

    public void unregister(String agentId, StreamObserver<Command> stream) {
        // 只在仍是本人注册时移除（避免新连接被旧连接的 onCompleted 回调误删）
        streams.remove(agentId, stream);
        log.info("Agent 下线: agent={} online={}", agentId, streams.size());
    }

    @Override
    public boolean send(String agentId, Command command) {
        StreamObserver<Command> stream = streams.get(agentId);
        if (stream == null) {
            return false;
        }
        try {
            stream.onNext(command);
            return true;
        } catch (Exception e) {
            log.warn("指令写入失败: agent={} err={}", agentId, e.getMessage());
            streams.remove(agentId, stream);
            return false;
        }
    }

    public int onlineCount() {
        return streams.size();
    }
}
