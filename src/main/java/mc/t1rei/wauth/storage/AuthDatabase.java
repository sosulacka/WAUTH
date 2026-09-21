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

import mc.t1rei.wauth.core.Crypto;
import mc.t1rei.wauth.core.AtomicFile;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public final class AuthDatabase implements AutoCloseable {
    public enum Table { ACCOUNTS, BINDINGS }

    private static final String KEY_CHECK = "WAUTH SQLite schema 1";
    private final Path directory;
    private final boolean encrypt;
    private final Crypto crypto;
    private final boolean removeLegacy;
    private final java.util.logging.Logger logger;
    private Connection connection;
    private boolean closed;

    public AuthDatabase(Path dataFolder, boolean encrypt, Crypto crypto) {
        this(dataFolder, encrypt, crypto, false, java.util.logging.Logger.getLogger(AuthDatabase.class.getName()));
    }

    public AuthDatabase(Path dataFolder, boolean encrypt, Crypto crypto, boolean removeLegacy, java.util.logging.Logger logger) {
        this.directory = dataFolder.resolve("data");
        this.encrypt = encrypt;
        this.crypto = crypto;
        this.removeLegacy = removeLegacy;
        this.logger = logger;
    }

    public synchronized void open() {
        if (connection != null) return;
        if (closed) throw new IllegalStateException("Storage is closed");
        try {
            if (encrypt && crypto == null) throw new IllegalStateException("Storage encryption key unavailable");
            Files.createDirectories(directory);
            Path file = directory.resolve("auth.sqlite");
            boolean existing = Files.exists(file);
            Path migrated = directory.resolve("sqlite.migrated");
            if (!existing && Files.exists(migrated)) {
                throw new IllegalStateException("SQLite database is missing after migration; restore a complete backup");
            }
            List<String> accounts = existing ? List.of() : legacy("accounts.db");
            List<String> bindings = existing ? List.of() : legacy("twofa.db");
            if (!existing) {
                StorageCodec.accounts(accounts);
                StorageCodec.bindings(bindings);
            }
            List<LegacyFiles.Entry> originals = existing ? List.of() : LegacyFiles.backup(directory);
            if (!existing && (!accounts.equals(legacy("accounts.db")) || !bindings.equals(legacy("twofa.db")))) {
                throw new IllegalStateException("Legacy database changed during migration");
            }
            connection = new org.sqlite.JDBC().connect("jdbc:sqlite:" + file, new java.util.Properties());
            try (Statement sql = connection.createStatement()) {
                sql.execute("PRAGMA busy_timeout=5000");
                sql.execute("PRAGMA journal_mode=WAL");
                sql.execute("PRAGMA synchronous=FULL");
                try (ResultSet result = sql.executeQuery("PRAGMA quick_check")) {
                    if (!result.next() || !"ok".equals(result.getString(1))) throw new SQLException("SQLite integrity check failed");
                }
            }
            if (!existing) migrate(accounts, bindings, originals);
            boolean wasEncrypted;
            try (Statement sql = connection.createStatement(); ResultSet result = sql.executeQuery("SELECT version, key_check FROM metadata WHERE id=1")) {
                if (!result.next() || result.getInt(1) != 1 || !KEY_CHECK.equals(decode(result.getString(2)))) {
                    throw new IllegalStateException("Missing or unsupported database schema or storage key");
                }
                wasEncrypted = result.getString(2).startsWith("CC1E:");
            }
            List<String> storedAccounts = read(Table.ACCOUNTS);
            List<String> storedBindings = read(Table.BINDINGS);
            StorageCodec.accounts(storedAccounts);
            StorageCodec.bindings(storedBindings);
            if (!existing && (!new java.util.HashSet<>(accounts).equals(new java.util.HashSet<>(storedAccounts))
                    || !new java.util.HashSet<>(bindings).equals(new java.util.HashSet<>(storedBindings)))) {
                throw new IllegalStateException("Imported records differ from legacy records");
            }
            if (wasEncrypted != encrypt) {
                transaction(() -> {
                    for (String row : storedAccounts) insert(Table.ACCOUNTS, rowId(row), row);
                    for (String row : storedBindings) insert(Table.BINDINGS, rowId(row), row);
                    try (PreparedStatement sql = connection.prepareStatement("UPDATE metadata SET key_check=? WHERE id=1")) {
                        sql.setString(1, encode(KEY_CHECK));
                        sql.executeUpdate();
                    }
                });
            }
            if (!Files.exists(migrated)) AtomicFile.write(migrated, KEY_CHECK + "\n");
            if (!existing) logger.info("SQLite import verified: " + storedAccounts.size() + " accounts, " + storedBindings.size() + " 2FA bindings");
            if (removeLegacy) cleanupLegacy();
        } catch (Exception failure) {
            try { close(); } catch (RuntimeException cleanup) { failure.addSuppressed(cleanup); }
            throw new IllegalStateException("Cannot initialize auth.sqlite; player logins must remain blocked", failure);
        }
    }

    private void migrate(List<String> accounts, List<String> bindings, List<LegacyFiles.Entry> originals) {
        transaction(() -> {
            LegacyFiles.verify(directory, originals);
            try (Statement sql = connection.createStatement()) {
                sql.execute("CREATE TABLE metadata (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, key_check TEXT NOT NULL)");
                sql.execute("CREATE TABLE accounts (id TEXT PRIMARY KEY, payload TEXT NOT NULL)");
                sql.execute("CREATE TABLE bindings (id TEXT PRIMARY KEY, payload TEXT NOT NULL)");
                sql.execute("CREATE TABLE legacy_import (name TEXT PRIMARY KEY, digest TEXT NOT NULL, backup TEXT NOT NULL)");
            }
            for (String row : accounts) insert(Table.ACCOUNTS, rowId(row), row);
            for (String row : bindings) insert(Table.BINDINGS, rowId(row), row);
            for (LegacyFiles.Entry entry : originals) {
                try (PreparedStatement sql = connection.prepareStatement("INSERT INTO legacy_import VALUES(?,?,?)")) {
                    sql.setString(1, entry.name());
                    sql.setString(2, entry.digest());
                    sql.setString(3, entry.backup());
                    sql.executeUpdate();
                }
            }
            try (PreparedStatement sql = connection.prepareStatement("INSERT INTO metadata(id,version,key_check) VALUES(1,1,?)")) {
                sql.setString(1, encode(KEY_CHECK));
                sql.executeUpdate();
            }
        });
    }

    private void cleanupLegacy() throws SQLException {
        try (Statement sql = connection.createStatement(); ResultSet result = sql.executeQuery(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='legacy_import'")) {
            if (!result.next()) return;
        }
        try (Statement sql = connection.createStatement(); ResultSet rows = sql.executeQuery("SELECT name,digest,backup FROM legacy_import")) {
            while (rows.next()) {
                var entry = new LegacyFiles.Entry(rows.getString(1), rows.getString(2), rows.getString(3));
                if (entry.name().equals("store.key") || !Files.exists(directory.resolve(entry.name()))) continue;
                try {
                    LegacyFiles.removeImported(directory, entry);
                    logger.info("Imported legacy file removed: " + entry.name() + "; backup: " + entry.backup());
                } catch (Exception failure) {
                    logger.warning("Legacy file retained: " + entry.name() + " (" + failure.getClass().getSimpleName() + ")");
                }
            }
        }
    }

    private List<String> legacy(String name) throws Exception {
        Path file = directory.resolve(name);
        if (!Files.exists(file)) return List.of();
        String content = Files.readString(file, StandardCharsets.UTF_8);
        if (content.isBlank()) throw new IllegalArgumentException("Empty legacy database: " + name);
        String plain = content.startsWith("CC1E:") || content.startsWith("CC1P:") ? decode(content) : content;
        return plain.lines().filter(line -> !line.isBlank()).toList();
    }

    public synchronized List<String> read(Table table) {
        requireOpen();
        try (Statement sql = connection.createStatement(); ResultSet rows = sql.executeQuery("SELECT id,payload FROM " + tableName(table))) {
            List<String> result = new ArrayList<>();
            while (rows.next()) {
                String plain = decode(rows.getString(2));
                if (!plain.startsWith(rows.getString(1) + "\t")) throw new IllegalArgumentException("Record identity mismatch");
                result.add(plain);
            }
            return result;
        } catch (Exception failure) {
            throw new IllegalStateException("Cannot read authentication storage", failure);
        }
    }

    public synchronized void write(Table table, UUID uuid, String payload) {
        requireOpen();
        if (!rowId(payload).equals(uuid)) throw new IllegalArgumentException("Record identity mismatch");
        validate(table, List.of(payload));
        transaction(() -> insert(table, uuid, payload));
    }

    public synchronized void delete(Table table, UUID uuid) {
        requireOpen();
        transaction(() -> {
            try (PreparedStatement sql = connection.prepareStatement("DELETE FROM " + tableName(table) + " WHERE id=?")) {
                sql.setString(1, uuid.toString());
                sql.executeUpdate();
            }
        });
    }

    public synchronized void writeBatch(Table table, List<String> payloads) {
        requireOpen();
        validate(table, payloads);
        transaction(() -> {
            for (String payload : payloads) insert(table, rowId(payload), payload);
        });
    }

    public synchronized void replace(Table table, List<String> payloads) {
        requireOpen();
        transaction(() -> {
            validate(table, payloads);
            try (Statement sql = connection.createStatement()) {
                sql.executeUpdate("DELETE FROM " + tableName(table));
            }
            for (String payload : payloads) {
                String[] fields = payload.split("\t", -1);
                insert(table, UUID.fromString(fields[0]), payload);
            }
        });
    }

    private void insert(Table table, UUID uuid, String payload) throws Exception {
        try (PreparedStatement sql = connection.prepareStatement("INSERT INTO " + tableName(table)
                + "(id,payload) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload")) {
            sql.setString(1, uuid.toString());
            sql.setString(2, encode(payload));
            sql.executeUpdate();
        }
    }

    private static UUID rowId(String row) {
        return UUID.fromString(row.substring(0, row.indexOf('\t')));
    }

    private static void validate(Table table, List<String> rows) {
        switch (table) {
            case ACCOUNTS -> StorageCodec.accounts(rows);
            case BINDINGS -> StorageCodec.bindings(rows);
        }
    }

    private void transaction(Change change) {
        Exception error = null;
        try {
            connection.setAutoCommit(false);
            try {
                change.run();
                connection.commit();
            } catch (Exception failure) {
                try { connection.rollback(); }
                catch (SQLException rollback) {
                    failure.addSuppressed(rollback);
                    try { close(); } catch (RuntimeException cleanup) { failure.addSuppressed(cleanup); }
                }
                throw failure;
            }
        } catch (Exception failure) {
            error = failure;
        } finally {
            if (!closed && connection != null) {
                try { connection.setAutoCommit(true); }
                catch (SQLException restore) {
                    if (error == null) error = restore;
                    else error.addSuppressed(restore);
                    try { close(); } catch (RuntimeException cleanup) { error.addSuppressed(cleanup); }
                }
            }
        }
        if (error != null) throw new IllegalStateException("Authentication transaction failed", error);
    }

    private String encode(String plain) throws Exception {
        return encrypt ? "CC1E:" + crypto.encrypt(plain) : "CC1P:" + plain;
    }

    private String decode(String payload) throws Exception {
        if (payload.startsWith("CC1P:")) return payload.substring(5);
        if (!payload.startsWith("CC1E:") || crypto == null) throw new IllegalStateException("Missing original encryption key");
        return crypto.decrypt(payload.substring(5));
    }

    private static String tableName(Table table) {
        return switch (table) { case ACCOUNTS -> "accounts"; case BINDINGS -> "bindings"; };
    }

    private void requireOpen() {
        if (closed || connection == null) throw new IllegalStateException("Authentication storage is unavailable");
    }

    @Override public synchronized void close() {
        closed = true;
        if (connection != null) {
            try { connection.close(); } catch (SQLException failure) { throw new IllegalStateException("Cannot close storage", failure); }
            finally { connection = null; }
        }
    }

    @FunctionalInterface private interface Change { void run() throws Exception; }
}
