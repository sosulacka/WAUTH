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

package mc.t1rei.wauth.twofa;

import mc.t1rei.wauth.PlayerStore;
import mc.t1rei.wauth.twofa.messenger.MessengerBot;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import static org.junit.jupiter.api.Assertions.*;

class TwoFactorAsyncTest {
    @TempDir Path dir;
    final Logger log = Logger.getLogger("TwoFactorAsyncTest");

    TwoFactorStore store(List<UUID> players) throws Exception {
        Files.createDirectories(dir.resolve("data"));
        StringBuilder rows = new StringBuilder("CC1P:");
        for (int i = 0; i < players.size(); i++) {
            rows.append(players.get(i)).append("\ttrue\tTELEGRAM\t").append(i + 1).append("\t\t1\n");
        }
        Files.writeString(dir.resolve("data/twofa.db"), rows.toString());
        TwoFactorStore store = new TwoFactorStore(dir, new PlayerStore(dir, null, log), log, false, null);
        store.load();
        return store;
    }

    @Test void slowBotsDoNotBlockCallerQueueIsBoundedAndCancelledRequestsAreSkipped() throws Exception {
        List<UUID> players = new ArrayList<>();
        for (int i = 0; i < 67; i++) players.add(UUID.randomUUID());
        TwoFactorManager manager = new TwoFactorManager(log, store(players), 60_000, 60_000, 1);
        CountDownLatch started = new CountDownLatch(2);
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch delivered = new CountDownLatch(65);
        var sent = ConcurrentHashMap.<String>newKeySet();
        manager.attachBots(new MessengerBot() {
            public void start() { }
            public void stop() { }
            public void sendConfirmation(String messengerId, String name, String token) {
                started.countDown();
                try { release.await(); }
                catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); return; }
                sent.add(messengerId);
                delivered.countDown();
            }
        }, null, null);
        try {
            assertTimeoutPreemptively(Duration.ofSeconds(2), () -> {
                assertTrue(manager.requestLogin(players.get(0), "P0", () -> {}, () -> {}).isPresent());
                assertTrue(manager.requestLogin(players.get(1), "P1", () -> {}, () -> {}).isPresent());
            });
            assertTrue(started.await(2, TimeUnit.SECONDS));
            for (int i = 2; i < 66; i++) {
                assertTrue(manager.requestLogin(players.get(i), "Player", () -> {}, () -> {}).isPresent());
            }
            assertTrue(manager.requestLogin(players.get(66), "Overflow", () -> fail("Overload approved"), () -> {}).isEmpty());
            assertFalse(manager.hasPendingLogin(players.get(66)));
            manager.cancel(players.get(2));
            release.countDown();
            assertTrue(delivered.await(5, TimeUnit.SECONDS));
            assertFalse(sent.contains("3"));
        } finally {
            release.countDown();
            manager.shutdown();
        }
    }

    @Test void deliveryFailureDeniesRequest() throws Exception {
        UUID player = UUID.randomUUID();
        TwoFactorManager manager = new TwoFactorManager(log, store(List.of(player)), 60_000, 60_000, 1);
        CountDownLatch denied = new CountDownLatch(1);
        manager.attachBots(new MessengerBot() {
            public void start() { }
            public void stop() { }
            public void sendConfirmation(String messengerId, String name, String token) { throw new IllegalStateException("offline"); }
        }, null, null);
        try {
            String token = manager.requestLogin(player, "Player", () -> fail("Failed delivery approved"), denied::countDown).orElseThrow();
            assertTrue(denied.await(2, TimeUnit.SECONDS));
            assertFalse(manager.resolve(token, true));
        } finally { manager.shutdown(); }
    }

    @Test void finalClickReturnsBeforeStorageCommitAndCodesArePublishedAfterCompletion() throws Exception {
        TwoFactorStore store = store(List.of());
        TwoFactorManager manager = new TwoFactorManager(log, store, 60_000, 60_000, 1);
        UUID player = UUID.randomUUID();
        try {
            var setup = manager.createSetup(player, "Player");
            manager.submitLinkCode(Provider.TELEGRAM, "123", setup.linkCode());
            assertEquals(2, manager.confirmLinkClick(player).join().remaining());
            assertEquals(1, manager.confirmLinkClick(player).join().remaining());
            CompletableFuture<TwoFactorManager.ConfirmResult> result;
            synchronized (store) {
                result = assertTimeoutPreemptively(Duration.ofSeconds(2), () -> manager.confirmLinkClick(player));
                assertFalse(result.isDone());
                assertFalse(manager.setupStatus(setup.sessionToken()).orElseThrow().linked());
            }
            assertTrue(result.get(10, TimeUnit.SECONDS).done());
            var status = manager.setupStatus(setup.sessionToken()).orElseThrow();
            assertTrue(status.linked());
            assertEquals(1, status.backup().size());
            assertNull(manager.setupStatus(setup.sessionToken()).orElseThrow().backup());
        } finally { manager.shutdown(); }
    }

    @Test void cancelledLinkCannotPublishIntoReplacementSetup() throws Exception {
        TwoFactorStore store = store(List.of());
        TwoFactorManager manager = new TwoFactorManager(log, store, 60_000, 60_000, 1);
        UUID player = UUID.randomUUID();
        try {
            var old = manager.createSetup(player, "Player");
            manager.submitLinkCode(Provider.TELEGRAM, "123", old.linkCode());
            manager.confirmLinkClick(player).join();
            manager.confirmLinkClick(player).join();
            CompletableFuture<TwoFactorManager.ConfirmResult> result;
            TwoFactorManager.SetupOpen replacement;
            synchronized (store) {
                result = manager.confirmLinkClick(player);
                replacement = manager.createSetup(player, "Player");
            }
            assertFalse(result.get(10, TimeUnit.SECONDS).known());
            assertFalse(store.isLinked(player));
            assertTrue(manager.setupStatus(old.sessionToken()).isEmpty());
            var status = manager.setupStatus(replacement.sessionToken()).orElseThrow();
            assertFalse(status.linked());
            assertNull(status.backup());
        } finally { manager.shutdown(); }
    }
}
