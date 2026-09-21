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

package mc.t1rei.wauth.storage;

import at.favre.lib.crypto.bcrypt.BCrypt;
import mc.t1rei.wauth.PlayerStore;
import mc.t1rei.wauth.core.Crypto;
import mc.t1rei.wauth.twofa.TwoFactorStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.util.List;
import java.util.Properties;
import java.util.UUID;
import java.util.logging.Logger;
import static org.junit.jupiter.api.Assertions.*;

class AuthDatabaseTest {
    @TempDir Path dir;
    final Logger log = Logger.getLogger("AuthDatabaseTest");
    final UUID id = UUID.randomUUID();

    String account() { return id + "\tPlayer\tpassword-hash\t1\t2\t127.0.0.1"; }
    String binding() { return id + "\ttrue\tTELEGRAM\t123456\t\t1"; }

    void legacy(String name, String content) throws Exception {
        Files.createDirectories(dir.resolve("data"));
        Files.writeString(dir.resolve("data/" + name), content);
    }

    AuthDatabase open(boolean encrypted, Crypto crypto) {
        AuthDatabase db = new AuthDatabase(dir, encrypted, crypto);
        db.open();
        return db;
    }

    Connection raw() throws Exception {
        return new org.sqlite.JDBC().connect("jdbc:sqlite:" + dir.resolve("data/auth.sqlite"), new Properties());
    }

    @Test void migratesBothLegacyStoresOnceAndLeavesOriginalsIntact() throws Exception {
        Crypto crypto = Crypto.load(dir.resolve("data/store.key"), log);
        String accounts = "CC1E:" + crypto.encrypt(account() + "\n");
        String bindings = "CC1P:" + binding() + "\n";
        legacy("accounts.db", accounts);
        legacy("twofa.db", bindings);
        try (var db = open(true, crypto)) {
            assertEquals(List.of(account()), db.read(AuthDatabase.Table.ACCOUNTS));
            assertEquals(List.of(binding()), db.read(AuthDatabase.Table.BINDINGS));
            db.delete(AuthDatabase.Table.ACCOUNTS, id);
            db.delete(AuthDatabase.Table.BINDINGS, id);
        }
        try (var db = open(true, crypto)) {
            assertTrue(db.read(AuthDatabase.Table.ACCOUNTS).isEmpty());
            assertTrue(db.read(AuthDatabase.Table.BINDINGS).isEmpty());
        }
        assertEquals(accounts, Files.readString(dir.resolve("data/accounts.db")));
        assertEquals(bindings, Files.readString(dir.resolve("data/twofa.db")));
    }

    @Test void damagedSecondFactorPreventsPartialAccountImportAndCanBeRepaired() throws Exception {
        legacy("accounts.db", "CC1P:" + account());
        legacy("twofa.db", "CC1P:broken");
        assertThrows(IllegalStateException.class, () -> open(false, null));
        assertFalse(Files.exists(dir.resolve("data/auth.sqlite")));
        legacy("twofa.db", "CC1P:" + binding());
        try (var db = open(false, null)) {
            assertEquals(1, db.read(AuthDatabase.Table.ACCOUNTS).size());
            assertEquals(1, db.read(AuthDatabase.Table.BINDINGS).size());
        }
    }

    @Test void duplicateAccountUuidsAndMessengerOwnershipAbortMigration() throws Exception {
        legacy("accounts.db", "CC1P:" + account() + "\n" + account());
        assertThrows(IllegalStateException.class, () -> open(false, null));
        legacy("accounts.db", "CC1P:" + account());
        legacy("twofa.db", "CC1P:" + binding() + "\n" + binding().replace(id.toString(), UUID.randomUUID().toString()));
        assertThrows(IllegalStateException.class, () -> open(false, null));
    }

    @Test void duplicateNamesKeepIndependentCredentialsAndRequireUuidForAdminTarget() throws Exception {
        UUID second = UUID.randomUUID();
        legacy("accounts.db", "CC1P:" + account() + "\n" + account().replace(id.toString(), second.toString())
                .replace("Player", "pLaYeR").replace("password-hash", "other-password"));
        legacy("twofa.db", "CC1P:" + binding());
        try (var db = open(false, null)) {
            PlayerStore accounts = new PlayerStore(dir, null, log, db);
            accounts.load();
            assertEquals(2, accounts.matchingIds("PLAYER").size());
            assertTrue(accounts.byName("Player").isEmpty());
            assertTrue(accounts.byTarget("Player").isEmpty());
            assertEquals("password-hash", accounts.byTarget(id.toString()).orElseThrow().hash());
            assertEquals("other-password", accounts.byTarget(second.toString()).orElseThrow().hash());
            assertTrue(accounts.updateHash(accounts.byUuid(id).orElseThrow(), "new"));
            assertEquals("other-password", accounts.byUuid(second).orElseThrow().hash());
            assertFalse(accounts.register(new PlayerStore.Account(UUID.randomUUID(), "Player", "third", 1, 1, "")));
            accounts.remove(id);
            assertEquals(second, accounts.byName("Player").orElseThrow().uuid());
            assertEquals(1, db.read(AuthDatabase.Table.BINDINGS).size());
        }
        try (var db = open(false, null)) {
            assertEquals("other-password", StorageCodec.accounts(db.read(AuthDatabase.Table.ACCOUNTS)).getFirst().hash());
        }
    }

    @Test void removesImportedFilesOnlyAfterVerifiedBackupAndPreservesKey() throws Exception {
        Crypto crypto = Crypto.load(dir.resolve("data/store.key"), log);
        String original = "CC1E:" + crypto.encrypt(account());
        legacy("accounts.db", original);
        legacy("twofa.db", "CC1P:" + binding());
        byte[] key = Files.readAllBytes(dir.resolve("data/store.key"));
        try (var db = new AuthDatabase(dir, true, crypto, true, log)) {
            db.open();
            assertEquals(List.of(account()), db.read(AuthDatabase.Table.ACCOUNTS));
            assertEquals(List.of(binding()), db.read(AuthDatabase.Table.BINDINGS));
            assertFalse(Files.exists(dir.resolve("data/accounts.db")));
            assertFalse(Files.exists(dir.resolve("data/twofa.db")));
            try (var backups = Files.list(dir.resolve("data/legacy-backup"))) {
                Path backup = backups.findFirst().orElseThrow();
                assertEquals(original, Files.readString(backup.resolve("accounts.db")));
                assertEquals("CC1P:" + binding(), Files.readString(backup.resolve("twofa.db")));
                assertArrayEquals(key, Files.readAllBytes(backup.resolve("store.key")));
            }
        }
        assertArrayEquals(key, Files.readAllBytes(dir.resolve("data/store.key")));
        try (var db = open(true, crypto)) { assertEquals(List.of(account()), db.read(AuthDatabase.Table.ACCOUNTS)); }
    }

    @Test void failedImportNeverRemovesSourceFiles() throws Exception {
        String source = "CC1P:" + account();
        legacy("accounts.db", source);
        legacy("twofa.db", "CC1P:broken");
        try (var db = new AuthDatabase(dir, false, null, true, log)) {
            assertThrows(IllegalStateException.class, db::open);
        }
        assertEquals(source, Files.readString(dir.resolve("data/accounts.db")));
        assertEquals("CC1P:broken", Files.readString(dir.resolve("data/twofa.db")));
    }

    @Test void retryCleanupDoesNotRemoveFilesChangedSinceImport() throws Exception {
        legacy("accounts.db", "CC1P:" + account());
        legacy("twofa.db", "CC1P:" + binding());
        try (var ignored = open(false, null)) { }
        String changed = "CC1P:" + account().replace("password-hash", "changed");
        legacy("accounts.db", changed);
        try (var db = new AuthDatabase(dir, false, null, true, log)) {
            db.open();
            assertEquals(changed, Files.readString(dir.resolve("data/accounts.db")));
            assertFalse(Files.exists(dir.resolve("data/twofa.db")));
            assertEquals(List.of(account()), db.read(AuthDatabase.Table.ACCOUNTS));
        }
    }

    @Test void retryCleanupRequiresIntactBackup() throws Exception {
        legacy("accounts.db", "CC1P:" + account());
        try (var ignored = open(false, null)) { }
        try (var backups = Files.list(dir.resolve("data/legacy-backup"))) {
            Files.writeString(backups.findFirst().orElseThrow().resolve("accounts.db"), "corrupt");
        }
        try (var db = new AuthDatabase(dir, false, null, true, log)) {
            db.open();
            assertEquals("CC1P:" + account(), Files.readString(dir.resolve("data/accounts.db")));
        }
    }

    @Test void truncatedDatabaseDoesNotReimportStaleAccounts() throws Exception {
        legacy("accounts.db", "CC1P:" + account());
        Files.write(dir.resolve("data/auth.sqlite"), new byte[0]);
        assertThrows(IllegalStateException.class, () -> open(false, null));
    }

    @Test void missingDatabaseAfterMigrationDoesNotRestoreLegacyCredentials() throws Exception {
        legacy("accounts.db", "CC1P:" + account());
        try (var ignored = open(false, null)) { }
        Files.delete(dir.resolve("data/auth.sqlite"));
        assertThrows(IllegalStateException.class, () -> open(false, null));
        assertFalse(Files.exists(dir.resolve("data/auth.sqlite")));
    }

    @Test void missingSchemaMarkerDoesNotReimportLegacyFiles() throws Exception {
        legacy("accounts.db", "CC1P:" + account());
        try (var db = open(false, null)) { db.delete(AuthDatabase.Table.ACCOUNTS, id); }
        try (var connection = raw(); var sql = connection.createStatement()) { sql.executeUpdate("DELETE FROM metadata"); }
        assertThrows(IllegalStateException.class, () -> open(false, null));
    }

    @Test void encryptionModeChangeRewritesAllRowsAndWrongKeyFails() throws Exception {
        legacy("accounts.db", "CC1P:" + account());
        legacy("twofa.db", "CC1P:" + binding());
        try (var ignored = open(false, null)) { }
        Crypto crypto = Crypto.load(dir.resolve("data/store.key"), log);
        try (var ignored = open(true, crypto)) { }
        try (var connection = raw(); var sql = connection.createStatement();
             var rows = sql.executeQuery("SELECT payload FROM accounts UNION ALL SELECT payload FROM bindings")) {
            while (rows.next()) {
                assertTrue(rows.getString(1).startsWith("CC1E:"));
                assertFalse(rows.getString(1).contains("password-hash"));
            }
        }
        Crypto wrong = Crypto.load(dir.resolve("wrong.key"), log);
        assertThrows(IllegalStateException.class, () -> open(true, wrong));
        assertThrows(IllegalStateException.class, () -> open(false, null));
        try (var db = open(false, crypto)) { assertEquals(List.of(account()), db.read(AuthDatabase.Table.ACCOUNTS)); }
        try (var db = open(false, null)) { assertEquals(List.of(binding()), db.read(AuthDatabase.Table.BINDINGS)); }
    }

    @Test void sqlFailureRollsBackDeletionAndEarlierInserts() throws Exception {
        try (var db = open(false, null)) {
            db.write(AuthDatabase.Table.ACCOUNTS, id, account());
            UUID blocked = UUID.randomUUID();
            try (var connection = raw(); var sql = connection.createStatement()) {
                sql.execute("CREATE TRIGGER reject_test BEFORE INSERT ON accounts WHEN NEW.id='" + blocked
                        + "' BEGIN SELECT RAISE(ABORT, 'simulated write failure'); END");
            }
            String changed = account().replace("password-hash", "new-hash");
            String rejected = account().replace(id.toString(), blocked.toString()).replace("Player", "Other");
            assertThrows(IllegalStateException.class, () -> db.replace(AuthDatabase.Table.ACCOUNTS, List.of(changed, rejected)));
            assertEquals(List.of(account()), db.read(AuthDatabase.Table.ACCOUNTS));
            db.write(AuthDatabase.Table.ACCOUNTS, id, changed);
        }
        try (var db = open(false, null)) {
            assertEquals(List.of(account().replace("password-hash", "new-hash")), db.read(AuthDatabase.Table.ACCOUNTS));
        }
    }

    @Test void failedCommitNeverPublishesCredentialChangesInMemory() throws Exception {
        try (var db = open(false, null)) {
            db.write(AuthDatabase.Table.ACCOUNTS, id, account());
            db.write(AuthDatabase.Table.BINDINGS, id, binding());
            PlayerStore accounts = new PlayerStore(dir, null, log, db);
            accounts.load();
            TwoFactorStore bindings = new TwoFactorStore(dir, accounts, log, false, null, db);
            bindings.load();
            var original = accounts.byUuid(id).orElseThrow();
            db.close();
            assertThrows(IllegalStateException.class, () -> accounts.updateHash(original, "new"));
            assertThrows(IllegalStateException.class, () -> accounts.remove(id));
            assertEquals(original, accounts.byUuid(id).orElseThrow());
            assertThrows(IllegalStateException.class, () -> bindings.setEnabled(id, false));
            assertThrows(IllegalStateException.class, () -> bindings.unbind(id));
            assertTrue(bindings.isActive(id));
            assertThrows(IllegalStateException.class, db::open);
        }
    }

    @Test void consumedRecoveryCodeStaysConsumedWithoutExplicitSave() throws Exception {
        String hash = BCrypt.withDefaults().hashToString(4, "ABCD-EFGH".toCharArray());
        try (var db = open(false, null)) {
            db.write(AuthDatabase.Table.BINDINGS, id, binding().replace("\t\t1", "\t" + hash + "\t1"));
            PlayerStore accounts = new PlayerStore(dir, null, log, db);
            TwoFactorStore bindings = new TwoFactorStore(dir, accounts, log, false, null, db);
            bindings.load();
            assertTrue(bindings.consumeBackup(id, "abcdefgh"));
        }
        try (var db = open(false, null)) {
            TwoFactorStore bindings = new TwoFactorStore(dir, new PlayerStore(dir, null, log, db), log, false, null, db);
            bindings.load();
            assertFalse(bindings.consumeBackup(id, "ABCD-EFGH"));
            assertEquals(0, bindings.backupLeft(id));
        }
    }

    @Test void metadataBatchDoesNotRestoreChangedPasswordsOrDeletedAccounts() throws Exception {
        try (var db = open(false, null)) {
            PlayerStore accounts = new PlayerStore(dir, null, log, db);
            accounts.load();
            var original = new PlayerStore.Account(id, "Player", "old", 1, 1, "");
            assertTrue(accounts.register(original));
            accounts.markLogin(original, "127.0.0.2");
            assertTrue(accounts.updateHash(original, "new"));
            accounts.markLogin(original, "127.0.0.3");
            accounts.save();
            var stored = StorageCodec.accounts(db.read(AuthDatabase.Table.ACCOUNTS)).getFirst();
            assertEquals("new", stored.hash());
            assertEquals("127.0.0.3", stored.lastIp());
            accounts.markLogin(original, "127.0.0.4");
            accounts.remove(id);
            accounts.save();
            assertTrue(db.read(AuthDatabase.Table.ACCOUNTS).isEmpty());
        }
    }

    @Test void metadataWriteFailureIsRetried() throws Exception {
        try (var db = open(false, null)) {
            PlayerStore accounts = new PlayerStore(dir, null, log, db);
            var original = new PlayerStore.Account(id, "Player", "hash", 1, 1, "old");
            accounts.put(original);
            accounts.markLogin(original, "new");
            try (var connection = raw(); var sql = connection.createStatement()) {
                sql.execute("CREATE TRIGGER reject_update BEFORE INSERT ON accounts BEGIN SELECT RAISE(ABORT, 'failure'); END");
                assertThrows(IllegalStateException.class, accounts::save);
                sql.execute("DROP TRIGGER reject_update");
            }
            accounts.save();
            assertEquals("new", StorageCodec.accounts(db.read(AuthDatabase.Table.ACCOUNTS)).getFirst().lastIp());
        }
    }
}
