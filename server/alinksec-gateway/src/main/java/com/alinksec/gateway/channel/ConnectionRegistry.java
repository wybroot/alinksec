package com.alinksec.gateway.channel;

import com.alinksec.proto.Command;
import io.grpc.stub.StreamObserver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Agent 在线连接注册表：agent_id → 下行 stream。
 * 实现 CommandSender：离线返回 false（指令保持 PENDING）。
 * 同一 agent 重复建流时踢旧连接（网络抖动快速重连场景）。
 */
@Component
public class ConnectionRegistry implements com.alinksec.service.command.CommandSender {

    private static final Logger log = LoggerFactory.getLogger(ConnectionRegistry.class);

    private static final class Connection {
        final StreamObserver<Command> stream;
        final AtomicInteger upgradeContract=new AtomicInteger(),isolationContract=new AtomicInteger(),weakPasswordContract=new AtomicInteger();
        final java.util.concurrent.locks.ReentrantReadWriteLock identity=new java.util.concurrent.locks.ReentrantReadWriteLock();
        final Object output=new Object();
        volatile boolean closed;
        Connection(StreamObserver<Command> stream) { this.stream=stream; }
        StreamObserver<Command> stream() { return stream; }
        AtomicInteger upgradeContract() { return upgradeContract; }
        AtomicInteger isolationContract() { return isolationContract; }
    }
    private final Map<String, Connection> streams = new ConcurrentHashMap<>();

    public void register(String agentId, StreamObserver<Command> stream) {
        Connection replacement=new Connection(stream);
        Connection old;
        for(;;) {
            old=streams.get(agentId);
            if(old==null) { if(streams.putIfAbsent(agentId,replacement)==null) break; }
            else {
                old.identity.writeLock().lock();
                try { synchronized(old.output) { if(streams.replace(agentId,old,replacement)) { old.closed=true; break; } } }
                finally { old.identity.writeLock().unlock(); }
            }
        }
        if (old != null) {
            log.info("重复建流，踢掉旧连接: agent={}", agentId);
            try {
                synchronized(old.output) { old.stream().onCompleted(); }
            } catch (Exception ignored) {
            }
        }
        log.info("Agent 上线: agent={} online={}", agentId, streams.size());
    }

    public void unregister(String agentId, StreamObserver<Command> stream) {
        // 只在仍是本人注册时移除（避免新连接被旧连接的 onCompleted 回调误删）
        Connection current=streams.get(agentId);
        if(current!=null) {
            current.identity.writeLock().lock();
            try { synchronized(current.output) { if(current.stream()==stream) { current.closed=true; streams.remove(agentId,current); } } }
            finally { current.identity.writeLock().unlock(); }
        }
        log.info("Agent 下线: agent={} online={}", agentId, streams.size());
    }

    @Override
    public boolean send(String agentId, Command command) {
        return send(agentId,command,null);
    }

    public boolean sendCurrent(String agentId,StreamObserver<Command> expected,Command command) {
        return send(agentId,command,expected);
    }

    private boolean send(String agentId,Command command,StreamObserver<Command> expected) {
        Connection connection = streams.get(agentId);
        if (connection == null) {
            return false;
        }
        synchronized(connection.output) {
        if(streams.get(agentId)!=connection || connection.closed || expected!=null && connection.stream()!=expected) return false;
        if (command.hasVulnScan() && command.getVulnScan().getIncludeWeakPassword()
                && (command.getVulnScan().getExecutionContract()!=1 || connection.weakPasswordContract.get()!=1)) return false;
        if (command.hasAgentUpgrade() && (command.getAgentUpgrade().getExecutionContract()!=1
                || connection.upgradeContract().get()!=1)) return false;
        if (command.hasProtectAction() && command.getProtectAction().getAction()==com.alinksec.proto.CmdProtectAction.Action.ISOLATE_HOST
                && (command.getProtectAction().getIsolationContract()!=1 || connection.isolationContract().get()!=1)) return false;
        if (command.hasProtectAction() && command.getProtectAction().getAction()==com.alinksec.proto.CmdProtectAction.Action.RESTORE_ISOLATION
                && command.getProtectAction().getIsolationContract()==1 && connection.isolationContract().get()!=1) return false;
        try {
            connection.stream().onNext(command);
            return true;
        } catch (Exception e) {
            log.warn("指令写入失败: agent={} err={}", agentId, e.getMessage());
            // Removing here would bypass the identity write lock while a
            // report is using its read lock. Keep the closing entry until its
            // callback/replacement retires it; reject further sends meanwhile.
            connection.closed=true;
            return false;
        }
        }
    }

    public void upgradeContract(String agentId,StreamObserver<Command> stream,int contract) {
        Connection current=streams.get(agentId);
        if(current!=null) synchronized(current.output) {
            if(streams.get(agentId)==current && current.stream()==stream) current.upgradeContract().set(contract==1?1:0);
        }
    }

    public void weakPasswordContract(String agentId,StreamObserver<Command> stream,int contract) {
        Connection current=streams.get(agentId);
        if(current!=null) synchronized(current.output) {
            if(streams.get(agentId)==current && current.stream()==stream) current.weakPasswordContract.set(contract==1?1:0);
        }
    }

    public void isolationContract(String agentId,StreamObserver<Command> stream,int contract) {
        Connection current=streams.get(agentId);
        if(current!=null) synchronized(current.output) {
            if(streams.get(agentId)==current && current.stream()==stream) current.isolationContract().set(contract==1?1:0);
        }
    }

    public boolean isolationCapable(String agentId,StreamObserver<Command> stream) {
        Connection current=streams.get(agentId);
        if(current==null) return false;
        synchronized(current.output) { return streams.get(agentId)==current && !current.closed && current.stream()==stream && current.isolationContract().get()==1; }
    }

    // Replacement and report processing share this identity lock. An echo can
    // never be sent through a replacement stream using an old stream's nonce.
    public void withCurrent(String agentId,StreamObserver<Command> stream,Runnable action) {
        Connection current=streams.get(agentId);
        if(current!=null) {
            current.identity.readLock().lock();
            try { if(streams.get(agentId)==current && !current.closed && current.stream()==stream) action.run(); }
            finally { current.identity.readLock().unlock(); }
        }
    }

    public int onlineCount() {
        return (int)streams.values().stream().filter(connection->!connection.closed).count();
    }
}
