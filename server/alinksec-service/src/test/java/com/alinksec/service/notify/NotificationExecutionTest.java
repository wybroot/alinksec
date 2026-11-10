package com.alinksec.service.notify;

import static org.junit.jupiter.api.Assertions.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class NotificationExecutionTest {
    @Test void burstUsesBoundedWorkersAndRunsOverflowOnCaller() throws Exception {
        var executor = new NotificationExecution().notificationExecutor();
        executor.initialize();
        var started = new CountDownLatch(2);
        var release = new CountDownLatch(1);
        var finished = new CountDownLatch(34);
        var delivered = new AtomicInteger();
        try {
            for (int i = 0; i < 2; i++) executor.execute(() -> {
                started.countDown();
                try { release.await(); delivered.incrementAndGet(); }
                catch (InterruptedException e) { Thread.currentThread().interrupt(); }
                finally { finished.countDown(); }
            });
            assertTrue(started.await(5, TimeUnit.SECONDS));
            for (int i = 0; i < 32; i++) executor.execute(() -> {
                delivered.incrementAndGet(); finished.countDown();
            });
            var overflow = new AtomicReference<Thread>();
            executor.execute(() -> { overflow.set(Thread.currentThread()); delivered.incrementAndGet(); });
            assertSame(Thread.currentThread(), overflow.get());
            assertEquals(2, executor.getPoolSize());
            assertEquals(32, executor.getQueueSize());
            release.countDown();
            assertTrue(finished.await(5, TimeUnit.SECONDS));
            assertEquals(35, delivered.get());
        } finally { release.countDown(); executor.shutdown(); }
    }
}
