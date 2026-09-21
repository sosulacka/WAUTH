/*
 * WAUTH - registration and login.
 * Copyright (C) 2026 CYN and T1REI
 *
 * Authors:
 *   CYN   - Discord: @syswow64deleted
 *   T1REI - Discord: @_t1rei_
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package mc.t1rei.wauth.core;

import org.junit.jupiter.api.Test;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

class BoundedExecutorTest {
    @Test void overloadNeverRunsOnCallerAndAcceptedJobsDrain() throws Exception {
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicReference<Thread> worker = new AtomicReference<>();
        AtomicInteger queued = new AtomicInteger();
        BoundedExecutor pool = new BoundedExecutor("test-worker", 1, 1);
        try {
            assertTrue(pool.submit(() -> {
                worker.set(Thread.currentThread());
                started.countDown();
                await(release);
            }));
            assertTrue(started.await(2, TimeUnit.SECONDS));
            assertTrue(pool.submit(queued::incrementAndGet));
            assertFalse(pool.submit(() -> fail("Rejected task ran")));
            assertNotSame(Thread.currentThread(), worker.get());
        } finally {
            release.countDown();
            pool.close();
        }
        assertEquals(1, queued.get());
        assertFalse(pool.submit(() -> fail("Closed pool accepted task")));
    }

    @Test void interruptedShutdownCancelsQueuedSecretsExactlyOnce() throws Exception {
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger cancelled = new AtomicInteger();
        BoundedExecutor pool = new BoundedExecutor("test-cancel", 1, 1);
        try {
            pool.submit(() -> { started.countDown(); await(release); });
            assertTrue(started.await(2, TimeUnit.SECONDS));
            assertTrue(pool.submit(() -> fail("Cancelled job ran"), cancelled::incrementAndGet));
            Thread.currentThread().interrupt();
            pool.close();
            assertTrue(Thread.interrupted());
            assertEquals(1, cancelled.get());
        } finally {
            Thread.interrupted();
            release.countDown();
            pool.close();
        }
        assertEquals(1, cancelled.get());
    }

    private static void await(CountDownLatch latch) {
        try { latch.await(); }
        catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
    }
}
