package com.alinksec.service.command;

import com.alinksec.proto.Command;

/** Receives command state changes that drive durable domain state. */
public interface CommandLifecycleListener {

    enum TerminalState {
        DONE,
        FAILED,
        TIMEOUT
    }

    default void onDispatched(String agentId, Command command) {
    }

    default void onTerminal(String agentId, String cmdId, TerminalState state, String message) {
    }

    default Command prepareDelivery(String agentId,Command command) { return command; }

    default void beforeAck(String agentId,String cmdId) { }
}
