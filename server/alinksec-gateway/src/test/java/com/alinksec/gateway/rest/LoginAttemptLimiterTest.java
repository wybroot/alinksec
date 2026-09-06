package com.alinksec.gateway.rest;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LoginAttemptLimiterTest {

    @Test
    void locksClientAfterFiveFailedAttempts() {
        LoginAttemptLimiter limiter = limiter();
        for (int i = 0; i < 5; i++) {
            assertTrue(limiter.isAllowed("192.0.2.1"));
            limiter.recordFailure("192.0.2.1");
        }

        assertFalse(limiter.isAllowed("192.0.2.1"));
        assertTrue(limiter.isAllowed("192.0.2.2"));
    }

    @Test
    void successfulLoginClearsPriorFailures() {
        LoginAttemptLimiter limiter = limiter();
        for (int i = 0; i < 4; i++) {
            limiter.recordFailure("192.0.2.1");
        }

        limiter.recordSuccess("192.0.2.1");
        for (int i = 0; i < 4; i++) {
            assertTrue(limiter.isAllowed("192.0.2.1"));
            limiter.recordFailure("192.0.2.1");
        }
        assertTrue(limiter.isAllowed("192.0.2.1"));
    }

    private static LoginAttemptLimiter limiter() {
        return new LoginAttemptLimiter(Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC));
    }
}
