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

package mc.t1rei.wauth;

import mc.t1rei.wauth.twofa.TwoFactorStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

class StorageSecurityTest {
    @TempDir Path dir;
    final Logger log = Logger.getLogger("StorageSecurityTest");

    @Test void refusesUnreadableAccountDatabaseAndNeverOverwritesIt() throws Exception {
        Files.createDirectories(dir.resolve("data"));
        Path file = dir.resolve("data/accounts.db");
        for (String damaged : new String[]{"CC1E:encrypted", "CC1P:broken-record"}) {
            Files.writeString(file, damaged);
            PlayerStore store = new PlayerStore(dir, null, log);
            assertThrows(IllegalStateException.class, store::load);
            store.put(new PlayerStore.Account(UUID.randomUUID(), "Player", "hash", 1, 1, "127.0.0.1"));
            store.save();
            assertEquals(damaged, Files.readString(file));
        }
    }

    @Test void refusesUnreadableSecondFactorDatabase() throws Exception {
        Files.createDirectories(dir.resolve("data"));
        Path file = dir.resolve("data/twofa.db");
        for (String damaged : new String[]{"CC1E:encrypted", "CC1P:broken-record",
                "CC1P:" + UUID.randomUUID() + "\twrong\tTELEGRAM\t1234\t\t1"}) {
            Files.writeString(file, damaged);
            TwoFactorStore store = new TwoFactorStore(dir, new PlayerStore(dir, null, log), log, false, null);
            assertThrows(IllegalStateException.class, store::load);
            store.save();
            assertEquals(damaged, Files.readString(file));
        }
    }

    @Test void delayedLoginCannotRestoreAnOldPasswordOrDeletedAccount() {
        PlayerStore store = new PlayerStore(dir, null, log);
        UUID uuid = UUID.randomUUID();
        PlayerStore.Account original = new PlayerStore.Account(uuid, "Player", "old", 1, 1, "");
        store.put(original);
        assertTrue(store.updateHash(original, "new"));
        store.markLogin(original, "127.0.0.1");
        assertEquals("new", store.byUuid(uuid).orElseThrow().hash());
        assertFalse(store.updateHash(original, "stale"));
        store.remove(uuid);
        store.markLogin(original, "127.0.0.1");
        assertFalse(store.updateHash(original, "resurrected"));
        assertFalse(store.isRegistered(uuid));
    }

    @Test void loadsAnAccountWithAnEmptyIp() throws Exception {
        Files.createDirectories(dir.resolve("data"));
        UUID uuid = UUID.randomUUID();
        Files.writeString(dir.resolve("data/accounts.db"), "CC1P:" + uuid + "\tPlayer\thash\t1\t1\t\n");
        PlayerStore store = new PlayerStore(dir, null, log);
        store.load();
        assertEquals("", store.byUuid(uuid).orElseThrow().lastIp());
    }
}
