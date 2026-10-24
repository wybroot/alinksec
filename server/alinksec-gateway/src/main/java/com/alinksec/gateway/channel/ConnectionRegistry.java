package com.alinksec.gateway.channel;

import com.alinksec.proto.Command;
import io.grpc.stub.StreamObserver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import com.alinksec.service.cluster.ClusterSessions;
import com.alinksec.service.cluster.ClusterUnavailable;
import java.util.function.Supplier;
import java.util.concurrent.locks.ReentrantLock;

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
        final ReentrantLock management=new ReentrantLock();
        String token="";
        volatile boolean ready;
        volatile boolean closed;
        Connection(StreamObserver<Command> stream) { this.stream=stream; }
        StreamObserver<Command> stream() { return stream; }
        AtomicInteger upgradeContract() { return upgradeContract; }
        AtomicInteger isolationContract() { return isolationContract; }
    }
    private final Map<String, Connection> streams = new ConcurrentHashMap<>();
    private final ClusterSessions sessions;
    private final java.util.concurrent.atomic.AtomicBoolean coordinationFailed=new java.util.concurrent.atomic.AtomicBoolean();
    private final Object[] registrationLocks=java.util.stream.IntStream.range(0,64).mapToObj(i->new Object()).toArray();

    public ConnectionRegistry() { this.sessions=null; }
    @org.springframework.beans.factory.annotation.Autowired
    public ConnectionRegistry(ClusterSessions sessions) { this.sessions=sessions; }
    @Override public boolean deferredDelivery() { return sessions!=null && sessions.enabled(); }

    public void register(String agentId, StreamObserver<Command> stream) {
        synchronized(registrationLocks[Math.floorMod(agentId.hashCode(),registrationLocks.length)]) {
        Connection replacement=new Connection(stream);
        Connection old;
        for(;;) {
            old=streams.get(agentId);
            if(old==null) {
                if(deferredDelivery()) replacement.token=sessions.claim(agentId);
                if(streams.putIfAbsent(agentId,replacement)==null) break;
            }
            else {
                old.identity.writeLock().lock();
                try {
                    if(streams.get(agentId)!=old) continue;
                    if(deferredDelivery()) replacement.token=sessions.claim(agentId);
                    synchronized(old.output) { if(streams.replace(agentId,old,replacement)) { old.closed=true; break; } }
                }
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
    }

    public void unregister(String agentId, StreamObserver<Command> stream) {
        // 只在仍是本人注册时移除（避免新连接被旧连接的 onCompleted 回调误删）
        Connection current=streams.get(agentId);
        boolean removed=false;
        if(current!=null) {
            current.identity.writeLock().lock();
            try { synchronized(current.output) { if(current.stream()==stream) { current.closed=true; removed=streams.remove(agentId,current); } } }
            finally { current.identity.writeLock().unlock(); }
        }
        if(removed) release(agentId,current);
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
        return inIdentity(agentId,connection,expected,()-> { synchronized(connection.output) {
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
        } },false);
    }

    @Override public <T> T withIdentity(String agentId,Supplier<T> action,T absent) {
        if(!deferredDelivery()) return action.get();
        Connection connection=streams.get(agentId);
        return connection==null || !connection.ready ? absent : inIdentity(agentId,connection,null,action,absent);
    }

    private <T> T inIdentity(String agentId,Connection connection,StreamObserver<Command> expected,Supplier<T> action,T absent) {
        connection.identity.readLock().lock();
        try {
            if(streams.get(agentId)!=connection || connection.closed || expected!=null && connection.stream()!=expected) return absent;
            if(!deferredDelivery()) return action.get();
            connection.management.lock();
            try { return sessions.current(agentId,connection.token,action); }
            catch(ClusterUnavailable failure) {
                connection.closed=true;
                if(!java.util.Set.of("agent_session_replaced_or_expired","agent_session_expired","agent_fence_busy").contains(failure.getMessage()))
                    coordinationFailed.set(true);
                return absent;
            }
            finally { connection.management.unlock(); }
        } finally {
            connection.identity.readLock().unlock();
            // A nested receipt send still holds its outer report's identity read lock.
            if(connection.closed && connection.identity.getReadHoldCount()==0) retire(agentId,connection);
        }
    }

    private void release(String agentId,Connection connection) {
        if(deferredDelivery() && !coordinationFailed.get() && sessions.ready()) try { sessions.release(agentId,connection.token); }
        catch(RuntimeException ignored) { /* Token comparison and TTL protect replacement ownership. */ }
    }

    private void retire(String agentId,Connection connection) {
        boolean removed;
        connection.identity.writeLock().lock();
        try { removed=streams.remove(agentId,connection);connection.closed=true; }
        finally { connection.identity.writeLock().unlock(); }
        if(removed) {
            release(agentId,connection);
            try { synchronized(connection.output) {
                connection.stream().onError(io.grpc.Status.UNAVAILABLE.withDescription("agent session is no longer owned by this node").asRuntimeException());
            } } catch(RuntimeException ignored) { }
        }
    }

    @org.springframework.scheduling.annotation.Scheduled(fixedDelay=5000,initialDelay=5000,scheduler="clusterScheduler")
    public void renewOwnership() {
        if(!deferredDelivery()) return;
        if(!sessions.healthy()) { coordinationFailed.set(true);closeOwnedStreams();return; }
        coordinationFailed.set(false);
        for(var entry:streams.entrySet()) {
            String agent=entry.getKey();Connection connection=entry.getValue();
            inIdentity(agent,connection,null,()-> {
                if(!sessions.renew(agent,connection.token)) throw new ClusterUnavailable("agent_session_expired");
                return true;
            },false);
            if(coordinationFailed.get()) { closeOwnedStreams();break; }
        }
    }

    @jakarta.annotation.PreDestroy
    public void closeOwnedStreams() {
        coordinationFailed.set(true);
        streams.forEach(this::retire);
    }

    public java.util.List<String> localAgentIds() {
        return streams.entrySet().stream().filter(e->!e.getValue().closed && (!deferredDelivery() || e.getValue().ready))
                .map(Map.Entry::getKey).sorted().toList();
    }

    public void heartbeatReady(String agent,StreamObserver<Command> expected) {
        Connection current=streams.get(agent);
        if(current!=null && current.stream()==expected && !current.closed) current.ready=true;
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
            inIdentity(agentId,current,stream,()-> { action.run();return null; },null);
        }
    }

    public int onlineCount() {
        return (int)streams.values().stream().filter(connection->!connection.closed).count();
    }
}
