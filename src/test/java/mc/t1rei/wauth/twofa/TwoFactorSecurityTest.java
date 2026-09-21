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

import at.favre.lib.crypto.bcrypt.BCrypt;
import mc.t1rei.wauth.PlayerStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

class TwoFactorSecurityTest {
    @TempDir Path dir;
    final Logger log = Logger.getLogger("TwoFactorSecurityTest");

    private TwoFactorStore store(UUID uuid) throws Exception {
        String hash = BCrypt.withDefaults().hashToString(4, "ABCD-EFGH".toCharArray());
        Files.createDirectories(dir.resolve("data"));
        Files.writeString(dir.resolve("data/twofa.db"), "CC1P:" + uuid + "\ttrue\tTELEGRAM\t123456\t" + hash + "\t1\n");
        TwoFactorStore store = new TwoFactorStore(dir, new PlayerStore(dir, null, log), log, false, null);
        store.load();
        return store;
    }

    @Test void acceptsBackupWithOrWithoutHyphenAndConsumesExactlyOnce() throws Exception {
        UUID uuid = UUID.randomUUID();
        TwoFactorStore store = store(uuid);
        try (var threads = Executors.newFixedThreadPool(4)) {
            Callable<Boolean> attempt = () -> store.consumeBackup(uuid, "abcdefgh");
            var results = threads.invokeAll(List.of(attempt, attempt, attempt, attempt));
            int accepted = 0;
            for (var result : results) if (result.get()) accepted++;
            assertEquals(1, accepted);
        }
        assertFalse(store.consumeBackup(uuid, "ABCD-EFGH"));
        store.save();
        TwoFactorStore loaded = new TwoFactorStore(dir, new PlayerStore(dir, null, log), log, false, null);
        loaded.load();
        assertFalse(loaded.consumeBackup(uuid, "ABCD-EFGH"));
    }

    @Test void cannotMoveMessengerOrOverwritePendingIdentity() throws Exception {
        UUID owner = UUID.randomUUID();
        TwoFactorStore store = store(owner);
        assertThrows(IllegalArgumentException.class, () -> store.bind(UUID.randomUUID(), Provider.TELEGRAM, "123456", 1));
        assertTrue(store.isActive(owner));
        TwoFactorManager manager = new TwoFactorManager(log, store, 60_000, 60_000, 1);
        UUID player = UUID.randomUUID();
        var setup = manager.createSetup(player, "Player");
        assertEquals(TwoFactorManager.LinkStatus.INVALID,
                manager.submitLinkCode(Provider.TELEGRAM, "123456", setup.linkCode()).status());
        assertEquals(TwoFactorManager.LinkStatus.NEEDS_CONFIRM,
                manager.submitLinkCode(Provider.TELEGRAM, "777", setup.linkCode()).status());
        assertEquals(2, manager.confirmLinkClick(player).join().remaining());
        assertEquals(TwoFactorManager.LinkStatus.INVALID,
                manager.submitLinkCode(Provider.VK, "888", setup.linkCode()).status());
        manager.submitLinkCode(Provider.TELEGRAM, "777", setup.linkCode());
        assertEquals(1, manager.confirmLinkClick(player).join().remaining());
        assertEquals("777", manager.pendingConfirm(player).orElseThrow().messengerId());
        manager.cancelSetup(player);
        assertFalse(manager.confirmLinkClick(player).join().known());
        assertTrue(manager.setupInfo(setup.sessionToken()).isEmpty());
        assertEquals(TwoFactorManager.LinkStatus.INVALID,
                manager.submitLinkCode(Provider.TELEGRAM, "777", setup.linkCode()).status());
    }

    @Test void messengerCallbackMustMatchOwnerAndProvider() throws Exception {
        UUID uuid = UUID.randomUUID();
        TwoFactorManager manager = new TwoFactorManager(log, store(uuid), 60_000, 60_000, 1);
        manager.attachBots(new mc.t1rei.wauth.twofa.messenger.MessengerBot() {
            public void start() { }
            public void stop() { }
            public void sendConfirmation(String id, String name, String token) { }
        }, null, null);
        AtomicInteger approvals = new AtomicInteger();
        String token = manager.requestLogin(uuid, "Player", approvals::incrementAndGet, () -> {}).orElseThrow();
        assertFalse(manager.resolve(token, true, Provider.TELEGRAM, "attacker"));
        assertFalse(manager.resolve(token, true, Provider.VK, "123456"));
        assertEquals(0, approvals.get());
        assertTrue(manager.resolve(token, true, Provider.TELEGRAM, "123456"));
        assertFalse(manager.resolve(token, true, Provider.TELEGRAM, "123456"));
        assertEquals(1, approvals.get());
        manager.shutdown();
    }
}
