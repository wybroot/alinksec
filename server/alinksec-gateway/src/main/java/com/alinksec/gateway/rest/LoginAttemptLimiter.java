package com.alinksec.gateway.rest;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

/** Limits unauthenticated login failures per trusted client address. */
@Service
public class LoginAttemptLimiter {

    private static final int MAX_FAILURES = 5;
    private static final int MAX_TRACKED_CLIENTS = 10_000;
    private static final Duration WINDOW = Duration.ofMinutes(10);
    private static final Duration LOCK_DURATION = Duration.ofMinutes(15);

    private final ConcurrentHashMap<String, Attempt> attempts = new ConcurrentHashMap<>();
    private final Clock clock;

    public LoginAttemptLimiter() {
        this(Clock.systemUTC());
    }

    LoginAttemptLimiter(Clock clock) {
        this.clock = clock;
    }

    public boolean isAllowed(String clientIp) {
        Attempt attempt = attempts.get(key(clientIp));
        if (attempt == null) {
            return true;
        }
        synchronized (attempt) {
            Instant now = clock.instant();
            attempt.lastSeen = now;
            if (attempt.lockedUntil != null) {
                if (now.isBefore(attempt.lockedUntil)) {
                    return false;
                }
                reset(attempt, now);
            } else if (!withinWindow(attempt, now)) {
                reset(attempt, now);
            }
            return true;
        }
    }

    public void recordFailure(String clientIp) {
        Instant now = clock.instant();
        String key = key(clientIp);
        Attempt attempt = attempts.get(key);
        if (attempt == null) {
            if (attempts.size() >= MAX_TRACKED_CLIENTS) {
                return;
            }
            Attempt created = new Attempt(now);
            Attempt existing = attempts.putIfAbsent(key, created);
            attempt = existing == null ? created : existing;
        }
        synchronized (attempt) {
            if (!withinWindow(attempt, now)) {
                reset(attempt, now);
            }
            attempt.lastSeen = now;
            attempt.failures++;
            if (attempt.failures >= MAX_FAILURES) {
                attempt.lockedUntil = now.plus(LOCK_DURATION);
            }
        }
    }

    public void recordSuccess(String clientIp) {
        attempts.remove(key(clientIp));
    }

    @Scheduled(fixedDelay = 600_000, initialDelay = 600_000)
    void purgeExpired() {
        Instant cutoff = clock.instant().minus(WINDOW.plus(LOCK_DURATION));
        attempts.entrySet().removeIf(entry -> entry.getValue().lastSeen.isBefore(cutoff));
    }

    private static boolean withinWindow(Attempt attempt, Instant now) {
        return !now.isAfter(attempt.windowStartedAt.plus(WINDOW));
    }

    private static void reset(Attempt attempt, Instant now) {
        attempt.failures = 0;
        attempt.windowStartedAt = now;
        attempt.lockedUntil = null;
    }

    private static String key(String clientIp) {
        return clientIp == null || clientIp.isBlank() ? "unknown" : clientIp;
    }

    private static final class Attempt {
        private int failures;
        private Instant windowStartedAt;
        private Instant lockedUntil;
        private volatile Instant lastSeen;

        private Attempt(Instant now) {
            this.windowStartedAt = now;
            this.lastSeen = now;
        }
    }
}
