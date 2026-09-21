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
import mc.t1rei.wauth.storage.AuthDatabase;
import mc.t1rei.wauth.storage.StorageCodec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

class BotAccountServiceTest {
    @TempDir Path dir;
    final Logger log = Logger.getLogger("BotAccountServiceTest");
    final UUID owner = UUID.randomUUID();
    final UUID other = UUID.randomUUID();

    private PlayerStore accounts() {
        PlayerStore accounts = new PlayerStore(dir, null, log);
        accounts.put(new PlayerStore.Account(owner, "Owner", BCrypt.withDefaults().hashToString(4, "old-secret".toCharArray()), 1, 2, "203.0.113.9"));
        accounts.put(new PlayerStore.Account(other, "Other", "other-hash", 1, 0, ""));
        return accounts;
    }

    private TwoFactorStore bindings(PlayerStore accounts) throws Exception {
        Files.createDirectories(dir.resolve("data"));
        Files.writeString(dir.resolve("data/twofa.db"), "CC1P:" + owner + "\ttrue\tTELEGRAM\t123\t\t1\n"
                + other + "\ttrue\tTELEGRAM\t456\t\t1\n");
        TwoFactorStore store = new TwoFactorStore(dir, accounts, log, false, null);
        store.load();
        return store;
    }

    @Test void lockNeedsOwnerConfirmationSurvivesReloadAndUnlockIsSeparate() throws Exception {
        PlayerStore accounts = accounts();
        AtomicInteger revoked = new AtomicInteger();
        try (var service = new BotAccountService(accounts, bindings(accounts), (name, pass) -> null, id -> {
            assertEquals(owner, id); revoked.incrementAndGet();
        }, 60_000)) {
            var prompt = service.handle(Provider.TELEGRAM, "123", "/ban").get(5, TimeUnit.SECONDS);
            assertNotNull(prompt.promptToken());
            assertFalse(accounts.isLocked(owner));
            service.handle(Provider.TELEGRAM, "456", "confirm:" + prompt.promptToken()).join();
            service.handle(Provider.VK, "123", "confirm:" + prompt.promptToken()).join();
            assertFalse(accounts.isLocked(owner));
            service.handle(Provider.TELEGRAM, "123", "confirm:" + prompt.promptToken()).join();
            service.handle(Provider.TELEGRAM, "123", "confirm:" + prompt.promptToken()).join();
            assertTrue(accounts.isLocked(owner));
            assertFalse(accounts.isLocked(other));
            assertEquals(1, revoked.get());
            PlayerStore loaded = new PlayerStore(dir, null, log);
            loaded.load();
            assertTrue(loaded.isLocked(owner));
            var unlock = service.handle(Provider.TELEGRAM, "123", "/unlock").join();
            assertTrue(accounts.isLocked(owner));
            service.handle(Provider.TELEGRAM, "123", "confirm:" + unlock.promptToken()).join();
            assertFalse(accounts.isLocked(owner));
            assertEquals(2, revoked.get());
        }
    }

    @Test void passwordRequiresCurrentSecretAndDoesNotChangeUntilConfirmed() throws Exception {
        PlayerStore accounts = accounts();
        AtomicInteger revoked = new AtomicInteger();
        try (var service = new BotAccountService(accounts, bindings(accounts), (name, pass) -> pass.length() < 8 ? "short" : null,
                id -> revoked.incrementAndGet(), 60_000)) {
            assertNull(service.handle(Provider.TELEGRAM, "123", "/password wrong new-secret").join().promptToken());
            assertNull(service.handle(Provider.TELEGRAM, "123", "/password old-secret short").join().promptToken());
            var prompt = service.handle(Provider.TELEGRAM, "123", "/password old-secret new-secret").get(10, TimeUnit.SECONDS);
            assertNotNull(prompt.promptToken());
            assertFalse(prompt.text().contains("new-secret"));
            assertTrue(accounts.verify("old-secret".toCharArray(), accounts.byUuid(owner).orElseThrow().hash()));
            var first = service.handle(Provider.TELEGRAM, "123", "confirm:" + prompt.promptToken());
            var replay = service.handle(Provider.TELEGRAM, "123", "confirm:" + prompt.promptToken());
            CompletableFuture.allOf(first, replay).join();
            assertEquals(1, revoked.get());
            assertTrue(accounts.verify("new-secret".toCharArray(), accounts.byUuid(owner).orElseThrow().hash()));
        }
    }

    @Test void cancelledExpiredAndChangedBindingCannotExecute() throws Exception {
        PlayerStore accounts = accounts();
        TwoFactorStore bindings = bindings(accounts);
        try (var service = new BotAccountService(accounts, bindings, (name, pass) -> null, id -> fail("Unexpected mutation"), 60_000)) {
            var cancelled = service.handle(Provider.TELEGRAM, "123", "/lock").join();
            service.handle(Provider.TELEGRAM, "123", "cancel:" + cancelled.promptToken()).join();
            service.handle(Provider.TELEGRAM, "123", "confirm:" + cancelled.promptToken()).join();
            var stale = service.handle(Provider.TELEGRAM, "123", "/lock").join();
            bindings.unbind(owner);
            service.handle(Provider.TELEGRAM, "123", "confirm:" + stale.promptToken()).join();
            assertFalse(accounts.isLocked(owner));
        }
        try (var expired = new BotAccountService(accounts, bindings(accounts), (name, pass) -> null, id -> fail("Expired mutation"), -1)) {
            var prompt = expired.handle(Provider.TELEGRAM, "123", "/lock").join();
            expired.handle(Provider.TELEGRAM, "123", "confirm:" + prompt.promptToken()).join();
            assertFalse(accounts.isLocked(owner));
        }
    }

    @Test void stalePasswordAndRateLimitRejectChanges() throws Exception {
        PlayerStore accounts = accounts();
        try (var service = new BotAccountService(accounts, bindings(accounts), (name, pass) -> null, id -> fail("Stale mutation"), 60_000)) {
            var prompt = service.handle(Provider.TELEGRAM, "123", "/lock").join();
            accounts.updateHash(accounts.byUuid(owner).orElseThrow(), "changed-by-admin");
            service.handle(Provider.TELEGRAM, "123", "confirm:" + prompt.promptToken()).join();
            assertFalse(accounts.isLocked(owner));
            for (int i = 0; i < 4; i++) service.handle(Provider.TELEGRAM, "123", "/lock").join();
            assertNull(service.handle(Provider.TELEGRAM, "123", "/lock").join().promptToken());
        }
    }

    @Test void sqliteKeepsLockThroughPasswordAndLoginUpdates() {
        try (var db = new AuthDatabase(dir, false, null)) {
            db.open();
            PlayerStore accounts = new PlayerStore(dir, null, log, db);
            accounts.put(new PlayerStore.Account(owner, "Owner", "hash", 1, 0, ""));
            assertTrue(accounts.setLocked(accounts.byUuid(owner).orElseThrow(), true));
            assertTrue(accounts.updateHash(accounts.byUuid(owner).orElseThrow(), "new-hash"));
            accounts.markLogin(accounts.byUuid(owner).orElseThrow(), "2001:db8::1");
            accounts.save();
        }
        try (var db = new AuthDatabase(dir, false, null)) {
            db.open();
            PlayerStore loaded = new PlayerStore(dir, null, log, db);
            loaded.load();
            assertTrue(loaded.isLocked(owner));
            assertEquals("new-hash", loaded.byUuid(owner).orElseThrow().hash());
            assertEquals("2001:db8::1", loaded.byUuid(owner).orElseThrow().lastIp());
        }
        assertThrows(IllegalArgumentException.class, () -> StorageCodec.accounts(List.of(owner + "\tOwner\thash\t1\t0\t\tnonsense")));
    }
}
