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
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.IntStream;
import static org.junit.jupiter.api.Assertions.*;

class AttemptLimiterTest {
    @Test void reconnectAndAddressChangeDoNotResetAccountBudget() {
        AtomicLong time = new AtomicLong(100);
        AttemptLimiter limiter = new AttemptLimiter(2, 10, 1000, 100, time::get);
        UUID player = UUID.randomUUID();
        assertEquals(0, limiter.acquire(player, "first"));
        assertEquals(0, limiter.acquire(player, "second"));
        time.set(200);
        assertEquals(900, limiter.acquire(player, "third"));
        time.set(1100);
        assertEquals(0, limiter.acquire(player, "first"));
    }

    @Test void changingAccountDoesNotResetAddressBudget() {
        AttemptLimiter limiter = new AttemptLimiter(10, 2, 1000, 100, () -> 0);
        assertEquals(0, limiter.acquire(UUID.randomUUID(), "shared"));
        assertEquals(0, limiter.acquire(UUID.randomUUID(), "shared"));
        UUID denied = UUID.randomUUID();
        assertEquals(1000, limiter.acquire(denied, "shared"));
        assertEquals(0, limiter.acquire(denied, "different"));
    }

    @Test void reservationsAreAtomicAcrossWorkers() throws Exception {
        AttemptLimiter limiter = new AttemptLimiter(5, 50, 1000, 100, () -> 0);
        UUID player = UUID.randomUUID();
        try (var threads = Executors.newFixedThreadPool(8)) {
            var results = threads.invokeAll(IntStream.range(0, 40)
                    .<java.util.concurrent.Callable<Long>>mapToObj(i -> () -> limiter.acquire(player, "shared")).toList());
            int admitted = 0;
            for (var result : results) if (result.get() == 0) admitted++;
            assertEquals(5, admitted);
        }
    }

    @Test void fullCapacityFailsClosedAndRecoversAfterExpiry() {
        AtomicLong time = new AtomicLong();
        AttemptLimiter limiter = new AttemptLimiter(5, 5, 1000, 2, time::get);
        UUID first = UUID.randomUUID();
        assertEquals(0, limiter.acquire(first, "first"));
        assertTrue(limiter.acquire(UUID.randomUUID(), "second") > 0);
        assertEquals(0, limiter.acquire(first, "first"));
        time.set(1000);
        assertEquals(0, limiter.acquire(UUID.randomUUID(), "second"));
    }
}
