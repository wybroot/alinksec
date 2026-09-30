package com.alinksec.gateway.rpc;

import com.alinksec.gateway.channel.ConnectionRegistry;
import com.alinksec.proto.Command;
import com.alinksec.proto.Report;
import com.alinksec.service.agent.AgentEntity;
import com.alinksec.service.agent.AgentRepository;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.report.ReportDispatcher;
import io.grpc.Context;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AgentChannelImplTest {

    @Test
    void rejectsLaterReportFromDifferentAgentOnAuthenticatedStream() {
        ReportDispatcher dispatcher = mock(ReportDispatcher.class);
        AgentRepository agents = mock(AgentRepository.class);
        ConnectionRegistry registry = mock(ConnectionRegistry.class);
        CommandService commands = mock(CommandService.class);
        AgentEntity agent = mock(AgentEntity.class);
        when(agent.status()).thenReturn(AgentEntity.STATUS_ONLINE);
        when(agents.findByAgentId("agent-a")).thenReturn(Optional.of(agent));
        @SuppressWarnings("unchecked")
        StreamObserver<Command> responses = mock(StreamObserver.class);
        var channel = new AgentChannelImpl(dispatcher, agents, registry, commands).channel(responses);
        Report first = Report.newBuilder().setAgentId("agent-a").build();
        Report forged = Report.newBuilder().setAgentId("agent-b").build();

        Context.current().withValue(AgentAuthInterceptor.AGENT_ID_KEY, "agent-a")
                .run(() -> {
                    channel.onNext(first);
                    channel.onNext(forged);
                    channel.onNext(first);
                });

        verify(dispatcher).dispatch("agent-a", first);
        verify(registry).unregister("agent-a", responses);
        verify(dispatcher, never()).dispatch(eq("agent-b"), any());
        org.mockito.ArgumentCaptor<Throwable> error = org.mockito.ArgumentCaptor.forClass(Throwable.class);
        verify(responses).onError(error.capture());
        assertEquals(Status.Code.PERMISSION_DENIED,
                Status.fromThrowable(error.getValue()).getCode());
    }
}
