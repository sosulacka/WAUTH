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

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.LongSupplier;

public final class AttemptLimiter {
    private record Window(int used, long until) {}
    private final Map<String, Window> windows = new HashMap<>();
    private final int accountLimit;
    private final int ipLimit;
    private final long windowMillis;
    private final int capacity;
    private final LongSupplier clock;

    public AttemptLimiter(int accountLimit, int ipLimit, long windowMillis, int capacity) {
        this(accountLimit, ipLimit, windowMillis, capacity, System::currentTimeMillis);
    }

    public AttemptLimiter(int accountLimit, int ipLimit, long windowMillis, int capacity, LongSupplier clock) {
        if (accountLimit < 1 || ipLimit < 1 || windowMillis < 1 || capacity < 2) {
            throw new IllegalArgumentException("Invalid attempt limiter settings");
        }
        this.accountLimit = accountLimit;
        this.ipLimit = ipLimit;
        this.windowMillis = windowMillis;
        this.capacity = capacity;
        this.clock = clock;
    }

    public synchronized long acquire(UUID uuid, String ip) {
        long now = clock.getAsLong();
        windows.values().removeIf(w -> w.until() <= now);
        String playerKey = "player:" + uuid;
        String ipKey = "ip:" + ip;
        Window player = windows.get(playerKey);
        Window address = windows.get(ipKey);
        long wait = 0;
        if (player != null && player.used() >= accountLimit) wait = player.until() - now;
        if (address != null && address.used() >= ipLimit) wait = Math.max(wait, address.until() - now);
        int newKeys = (player == null ? 1 : 0) + (address == null ? 1 : 0);
        if (windows.size() + newKeys > capacity) wait = Math.max(wait, windowMillis);
        if (wait > 0) return wait;
        windows.put(playerKey, increment(player, now));
        windows.put(ipKey, increment(address, now));
        return 0;
    }

    private Window increment(Window previous, long now) {
        return previous == null ? new Window(1, now + windowMillis)
                : new Window(previous.used() + 1, previous.until());
    }
}
