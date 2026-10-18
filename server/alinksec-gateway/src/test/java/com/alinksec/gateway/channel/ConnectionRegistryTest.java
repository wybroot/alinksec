package com.alinksec.gateway.channel;

import com.alinksec.proto.*;
import io.grpc.stub.StreamObserver;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ConnectionRegistryTest {
    @Test void weakPasswordCapabilityCannotCarryAcrossReplacementOrOldHeartbeats() {
        var registry=new ConnectionRegistry();
        @SuppressWarnings("unchecked") StreamObserver<Command> first=mock(StreamObserver.class),second=mock(StreamObserver.class);
        var scan=Command.newBuilder().setVulnScan(CmdVulnScan.newBuilder().setIncludeWeakPassword(true).setExecutionContract(1)).build();
        registry.register("agent",first);assertFalse(registry.send("agent",scan));
        registry.weakPasswordContract("agent",first,1);assertTrue(registry.send("agent",scan));
        registry.register("agent",second);registry.weakPasswordContract("agent",first,1);
        assertFalse(registry.send("agent",scan));verifyNoInteractions(second);
        registry.weakPasswordContract("agent",second,1);assertTrue(registry.send("agent",scan));
        registry.weakPasswordContract("agent",second,0);assertFalse(registry.send("agent",scan));
    }

    @Test void isolationCapabilityAndEchoAreBoundToTheCurrentStream() {
        var registry=new ConnectionRegistry();
        @SuppressWarnings("unchecked") StreamObserver<Command> first=mock(StreamObserver.class),second=mock(StreamObserver.class);
        var isolate=Command.newBuilder().setProtectAction(CmdProtectAction.newBuilder().setAction(CmdProtectAction.Action.ISOLATE_HOST).setIsolationContract(1)).build();
        registry.register("agent",first);
        assertFalse(registry.send("agent",isolate));
        registry.isolationContract("agent",first,1);
        assertTrue(registry.send("agent",isolate));
        registry.register("agent",second);
        registry.isolationContract("agent",first,1);
        registry.withCurrent("agent",first,()->fail("superseded stream processed live isolation state"));
        assertFalse(registry.send("agent",isolate));
        assertFalse(registry.isolationCapable("agent",second));
        verifyNoInteractions(second);
        registry.isolationContract("agent",second,1);
        assertTrue(registry.send("agent",isolate));
    }

    @Test void reportDatabaseWorkDoesNotBlockAnOutgoingCommandHoldingADatabaseWriteLock() throws Exception {
        var registry=new ConnectionRegistry();
        @SuppressWarnings("unchecked") StreamObserver<Command> first=mock(StreamObserver.class),second=mock(StreamObserver.class);
        registry.register("agent",first);
        var entered=new java.util.concurrent.CountDownLatch(1);
        var release=new java.util.concurrent.CountDownLatch(1);
        try(var threads=java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor()) {
            var processing=threads.submit(()->registry.withCurrent("agent",first,()-> {
                entered.countDown();
                try { assertTrue(release.await(3,java.util.concurrent.TimeUnit.SECONDS)); }
                catch(InterruptedException e) { throw new AssertionError(e); }
            }));
            try {
                assertTrue(entered.await(2,java.util.concurrent.TimeUnit.SECONDS));
                var send=threads.submit(()->registry.send("agent",Command.newBuilder().setCollectNow(CmdCollectNow.getDefaultInstance()).build()));
                assertTrue(send.get(1,java.util.concurrent.TimeUnit.SECONDS),"report/send lock inversion can deadlock a pending SQLite transaction");
            } finally { release.countDown(); }
            processing.get(2,java.util.concurrent.TimeUnit.SECONDS);
            registry.register("agent",second);
            registry.withCurrent("agent",first,()->fail("old stream remained current"));
        }
    }
    @Test void staleConnectionCannotAuthorizeUpgradeOnAnUnqualifiedReplacement() {
        var registry=new ConnectionRegistry();
        @SuppressWarnings("unchecked") StreamObserver<Command> first=mock(StreamObserver.class),second=mock(StreamObserver.class);
        Command upgrade=Command.newBuilder().setAgentUpgrade(CmdAgentUpgrade.newBuilder().setExecutionContract(1)).build();
        registry.register("agent",first);assertFalse(registry.send("agent",upgrade));
        registry.upgradeContract("agent",first,1);assertTrue(registry.send("agent",upgrade));
        registry.register("agent",second);verify(first).onCompleted();
        registry.upgradeContract("agent",first,1);registry.unregister("agent",first);
        assertFalse(registry.send("agent",upgrade));verifyNoInteractions(second);
        registry.upgradeContract("agent",second,1);assertTrue(registry.send("agent",upgrade));
        registry.upgradeContract("agent",second,0);assertFalse(registry.send("agent",upgrade));
        registry.upgradeContract("agent",second,1);
        assertFalse(registry.send("agent",upgrade.toBuilder().setAgentUpgrade(CmdAgentUpgrade.getDefaultInstance()).build()));
        registry.unregister("agent",second);assertEquals(0,registry.onlineCount());
    }
}
