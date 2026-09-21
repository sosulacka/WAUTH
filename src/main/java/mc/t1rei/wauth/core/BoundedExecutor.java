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

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public final class BoundedExecutor implements AutoCloseable {
    private final ThreadPoolExecutor executor;

    public BoundedExecutor(String name, int threads, int capacity) {
        executor = new ThreadPoolExecutor(threads, threads, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(capacity), task -> {
                    Thread thread = new Thread(task, name);
                    thread.setDaemon(true);
                    return thread;
                });
    }

    public boolean submit(Runnable task) {
        return submit(task, () -> {});
    }

    public boolean submit(Runnable task, Runnable cancelled) {
        try {
            executor.execute(new Job(task, cancelled));
            return true;
        } catch (RejectedExecutionException rejected) {
            return false;
        }
    }

    @Override
    public void close() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) cancelQueued();
        } catch (InterruptedException interrupted) {
            cancelQueued();
            Thread.currentThread().interrupt();
        }
    }

    private void cancelQueued() {
        for (Runnable task : executor.shutdownNow()) ((Job) task).cancelled().run();
    }

    private record Job(Runnable task, Runnable cancelled) implements Runnable {
        @Override public void run() { task.run(); }
    }
}
