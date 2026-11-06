package com.alinksec.gateway.rest;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Limits unauthenticated login failures per trusted client address and username.
 * R25: 解决单机限流容量耗尽导致攻击逃逸漏洞，引入双维度防护(IP+账号)与有界过期/LRU驱逐机制。
 */
@Service
public class LoginAttemptLimiter {

    private static final int MAX_FAILURES = 5;
    private static final int MAX_TRACKED_CLIENTS = 10_000;
    private static final Duration WINDOW = Duration.ofMinutes(10);
    private static final Duration LOCK_DURATION = Duration.ofMinutes(15);

    private final ConcurrentHashMap<String, Attempt> attempts = new ConcurrentHashMap<>();
    private final Clock clock;
    @org.springframework.beans.factory.annotation.Autowired
    private com.alinksec.service.cluster.ClusterLoginLimiter clustered;

    public LoginAttemptLimiter() {
        this(Clock.systemUTC());
    }

    LoginAttemptLimiter(Clock clock) {
        this.clock = clock;
    }

    public boolean isAllowed(String clientIp) {
        return isAllowed(clientIp, null);
    }

    public boolean isAllowed(String clientIp, String username) {
        if (clustered != null && clustered.enabled()) return clustered.apply(clientIp, "check");
        if (!checkAllowedForKey(keyIp(clientIp))) {
            return false;
        }
        if (username != null && !username.isBlank()) {
            return checkAllowedForKey(keyUser(username));
        }
        return true;
    }

    private boolean checkAllowedForKey(String k) {
        Attempt attempt = attempts.get(k);
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
        recordFailure(clientIp, null);
    }

    public void recordFailure(String clientIp, String username) {
        if (clustered != null && clustered.enabled()) {
            clustered.apply(clientIp, "failure");
            return;
        }
        recordFailureForKey(keyIp(clientIp));
        if (username != null && !username.isBlank()) {
            recordFailureForKey(keyUser(username));
        }
    }

    private void recordFailureForKey(String k) {
        Instant now = clock.instant();
        Attempt attempt = attempts.get(k);
        if (attempt == null) {
            if (attempts.size() >= MAX_TRACKED_CLIENTS) {
                purgeExpired();
                if (attempts.size() >= MAX_TRACKED_CLIENTS) {
                    evictOldestEntry();
                }
            }
            Attempt created = new Attempt(now);
            Attempt existing = attempts.putIfAbsent(k, created);
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
        recordSuccess(clientIp, null);
    }

    public void recordSuccess(String clientIp, String username) {
        if (clustered != null && clustered.enabled()) {
            clustered.apply(clientIp, "success");
            return;
        }
        attempts.remove(keyIp(clientIp));
        if (username != null && !username.isBlank()) {
            attempts.remove(keyUser(username));
        }
    }

    private void evictOldestEntry() {
        String oldestKey = null;
        Instant oldestSeen = Instant.MAX;
        Instant now = clock.instant();
        for (var entry : attempts.entrySet()) {
            Attempt a = entry.getValue();
            boolean isLocked = a.lockedUntil != null && now.isBefore(a.lockedUntil);
            if (!isLocked && a.lastSeen.isBefore(oldestSeen)) {
                oldestSeen = a.lastSeen;
                oldestKey = entry.getKey();
            }
        }
        if (oldestKey == null && !attempts.isEmpty()) {
            oldestKey = attempts.keySet().iterator().next();
        }
        if (oldestKey != null) {
            attempts.remove(oldestKey);
        }
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

    private static String keyIp(String clientIp) {
        return "ip:" + (clientIp == null || clientIp.isBlank() ? "unknown" : clientIp);
    }

    private static String keyUser(String username) {
        return "user:" + (username == null || username.isBlank() ? "unknown" : username.trim().toLowerCase());
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
