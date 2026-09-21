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
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CryptoTest {

    private static final Logger LOGGER = Logger.getLogger(CryptoTest.class.getName());

    @Test
    void roundTripsUnicodePayload(@TempDir Path dir) throws Exception {
        Crypto crypto = Crypto.load(dir.resolve("store.key"), LOGGER);
        String plain = "uuid\ttrue\tDISCORD\t123456789\thash1;hash2\t999\nкириллица 🔐";
        String encrypted = crypto.encrypt(plain);
        assertNotEquals(plain, encrypted);
        assertEquals(plain, crypto.decrypt(encrypted));
    }

    @Test
    void reusesPersistedKeyAcrossInstances(@TempDir Path dir) throws Exception {
        Path key = dir.resolve("store.key");
        Crypto first = Crypto.load(key, LOGGER);
        String encrypted = first.encrypt("secret-payload");

        Crypto second = Crypto.load(key, LOGGER);
        assertEquals("secret-payload", second.decrypt(encrypted));
    }

    @Test
    void usesFreshIvPerEncryption(@TempDir Path dir) throws Exception {
        Crypto crypto = Crypto.load(dir.resolve("store.key"), LOGGER);
        assertNotEquals(crypto.encrypt("same"), crypto.encrypt("same"));
    }

    @Test
    void writesKeyFileOnFirstLoad(@TempDir Path dir) throws Exception {
        Path key = dir.resolve("store.key");
        Crypto.load(key, LOGGER);
        assertTrue(Files.exists(key), "ключ не создан");
        assertTrue(Files.size(key) > 0, "файл ключа пуст");
    }

    @Test
    void neverReplacesDamagedKey(@TempDir Path dir) throws Exception {
        Path key = dir.resolve("store.key");
        Files.writeString(key, "AA==");
        org.junit.jupiter.api.Assertions.assertThrows(java.io.IOException.class, () -> Crypto.load(key, LOGGER));
        assertEquals("AA==", Files.readString(key));
    }
}
