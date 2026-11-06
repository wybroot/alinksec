package com.alinksec.service.notify;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class NotifyServiceTest {

    @Test
    void inspectBotResponseParsesDingTalkAndWeComSuccess() {
        assertNull(NotifyService.inspectBotResponse("{\"errcode\":0,\"errmsg\":\"ok\"}"));
    }

    @Test
    void inspectBotResponseDetectsDingTalkAndWeComError() {
        String err = NotifyService.inspectBotResponse("{\"errcode\":93000,\"errmsg\":\"invalid webhook url\"}");
        assertEquals("bot_rejected: invalid webhook url", err);
    }

    @Test
    void inspectBotResponseDetectsFeishuError() {
        String err = NotifyService.inspectBotResponse("{\"code\":19001,\"msg\":\"param invalid\"}");
        assertEquals("bot_rejected: param invalid", err);

        String legacyErr = NotifyService.inspectBotResponse("{\"StatusCode\":19002,\"StatusMessage\":\"token expired\"}");
        assertEquals("bot_rejected: token expired", legacyErr);
    }

    @Test
    void inspectBotResponseIgnoresPlainJsonOrNonJson() {
        assertNull(NotifyService.inspectBotResponse("{\"status\":\"success\"}"));
        assertNull(NotifyService.inspectBotResponse("OK"));
    }
}
