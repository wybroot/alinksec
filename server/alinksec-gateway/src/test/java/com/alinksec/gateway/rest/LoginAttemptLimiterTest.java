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

    @Test
    void locksAccountAcrossDifferentIps() {
        LoginAttemptLimiter limiter = limiter();
        for (int i = 0; i < 5; i++) {
            String ip = "192.0.2." + (i + 1);
            assertTrue(limiter.isAllowed(ip, "victim_user"));
            limiter.recordFailure(ip, "victim_user");
        }

        // Distinct 6th IP attempting login for same victim_user should be blocked
        assertFalse(limiter.isAllowed("192.0.2.100", "victim_user"));
        // Different user from 6th IP should still be allowed
        assertTrue(limiter.isAllowed("192.0.2.100", "other_user"));
    }

    private static LoginAttemptLimiter limiter() {
        return new LoginAttemptLimiter(Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC));
    }
}
