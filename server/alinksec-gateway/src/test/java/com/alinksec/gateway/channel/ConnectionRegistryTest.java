package com.alinksec.gateway.channel;

import com.alinksec.proto.*;
import io.grpc.stub.StreamObserver;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ConnectionRegistryTest {
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
