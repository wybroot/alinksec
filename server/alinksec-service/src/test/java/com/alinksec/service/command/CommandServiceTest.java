package com.alinksec.service.command;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.CmdCollectNow;
import com.alinksec.proto.Command;
import com.alinksec.service.download.AgentDownloadTokenService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Base64;

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

    @Test
    void dispatchPersistsCompleteProtobufForReplay() throws Exception {
        when(sender.send(eq("agent-1"), org.mockito.ArgumentMatchers.any(Command.class))).thenReturn(false);
        CommandService service = new CommandService(repository, sender, downloadTokens);

        service.dispatch("agent-1", Command.newBuilder().setCollectNow(CmdCollectNow.getDefaultInstance()), null);

        ArgumentCaptor<String> payload = ArgumentCaptor.forClass(String.class);
        verify(repository).insert(anyString(), eq("agent-1"), eq("collect_now"), payload.capture(), isNull());
        String encoded = JsonUtils.read(payload.getValue()).path("command_b64").asText();
        Command saved = Command.parseFrom(Base64.getDecoder().decode(encoded));
        assertEquals(Command.PayloadCase.COLLECT_NOW, saved.getPayloadCase());
        assertTrue(saved.getCmdId().length() > 10);
    }
}
