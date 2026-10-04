package com.alinksec.service.command;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.CmdAgentUpgrade;
import com.alinksec.proto.CmdCollectNow;
import com.alinksec.proto.Command;
import com.alinksec.proto.RptAck;
import com.alinksec.service.download.AgentDownloadTokenService;
import com.alinksec.service.config.AlinkSecProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CommandServiceTest {

    @Mock private CommandRepository repository;
    @Mock private CommandSender sender;
    @Mock private AgentDownloadTokenService downloadTokens;
    @Mock private CommandLifecycleListener lifecycleListener;
    @Mock private org.springframework.transaction.PlatformTransactionManager transactionManager;

    @Test
    void dispatchPersistsCompleteProtobufForReplay() throws Exception {
        when(sender.send(eq("agent-1"), org.mockito.ArgumentMatchers.any(Command.class))).thenReturn(false);
        CommandService service = new CommandService(repository, sender, downloadTokens,
                new AlinkSecProperties(), List.of(lifecycleListener), transactionManager);

        service.dispatch("agent-1", Command.newBuilder().setCollectNow(CmdCollectNow.getDefaultInstance()), null);

        ArgumentCaptor<String> payload = ArgumentCaptor.forClass(String.class);
        verify(repository).insert(anyString(), eq("agent-1"), eq("collect_now"), payload.capture(), isNull());
        String encoded = JsonUtils.read(payload.getValue()).path("command_b64").asText();
        Command saved = Command.parseFrom(Base64.getDecoder().decode(encoded));
        assertEquals(Command.PayloadCase.COLLECT_NOW, saved.getPayloadCase());
        assertTrue(saved.getCmdId().length() > 10);
    }

    @Test
    void deliverPendingRefreshesLegacyHttpUpgradeUrlUsingConfiguredHttpsBase() {
        AlinkSecProperties props = new AlinkSecProperties();
        props.getUpgrade().setDownloadBaseUrl("https://console.example.test:8443");
        Command saved = Command.newBuilder().setAgentUpgrade(CmdAgentUpgrade.newBuilder()
                .setDownloadUrl("http://legacy.example.test:8080/api/upgrade/download?packageKey=agent-v1.bin&token=expired"))
                .build();
        Map<String, Object> row = Map.of(
                "cmd_id", "cmd-1",
                "payload", JsonUtils.write(Map.of("command_b64",
                        Base64.getEncoder().encodeToString(saved.toByteArray()))));
        when(repository.findPendingByAgent("agent-1")).thenReturn(List.of(row));
        when(downloadTokens.issue("agent-1", "agent-upgrade", "agent-v1.bin")).thenReturn("fresh-token");
        when(sender.send(eq("agent-1"), org.mockito.ArgumentMatchers.any(Command.class))).thenReturn(true);
        CommandService service = new CommandService(repository, sender, downloadTokens, props,
                List.of(lifecycleListener), transactionManager);

        service.deliverPending("agent-1");

        ArgumentCaptor<Command> sent = ArgumentCaptor.forClass(Command.class);
        verify(sender).send(eq("agent-1"), sent.capture());
        assertEquals("https://console.example.test:8443/api/upgrade/download?packageKey=agent-v1.bin&token=fresh-token",
                sent.getValue().getAgentUpgrade().getDownloadUrl());
        verify(repository).markSent("cmd-1");
    }

    @Test
    void terminalAckNotifiesDomainListenerOnlyAfterCommandRowWasUpdated() {
        RptAck ack = RptAck.newBuilder()
                .setCmdId("cmd-1")
                .setStage(RptAck.Stage.DONE)
                .setMessage("ok")
                .build();
        when(repository.onAck("agent-1", ack)).thenReturn(1);
        CommandService service = new CommandService(repository, sender, downloadTokens,
                new AlinkSecProperties(), List.of(lifecycleListener), transactionManager);

        service.onAck("agent-1", ack);

        org.mockito.InOrder order = org.mockito.Mockito.inOrder(repository, lifecycleListener);
        order.verify(repository).onAck("agent-1", ack);
        order.verify(lifecycleListener).onTerminal("agent-1", "cmd-1",
                CommandLifecycleListener.TerminalState.DONE, "ok");
    }
}
