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
import mc.t1rei.wauth.core.Crypto;
import mc.t1rei.wauth.core.AtomicFile;
import mc.t1rei.wauth.storage.AuthDatabase;
import mc.t1rei.wauth.storage.StorageCodec;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Logger;

public final class TwoFactorStore {

    public record Binding(UUID uuid, boolean enabled, Provider provider, String messengerId,
                          List<String> backupHashes, long createdAt) {
        public Binding {
            backupHashes = List.copyOf(backupHashes);
        }

        public boolean linked() {
            return provider != null && messengerId != null && !messengerId.isBlank();
        }

        Binding withEnabled(boolean value) {
            return new Binding(uuid, value, provider, messengerId, backupHashes, createdAt);
        }

        Binding withBackup(List<String> hashes) {
            return new Binding(uuid, enabled, provider, messengerId, hashes, createdAt);
        }
    }

    private static final String ENCRYPTED_PREFIX = "CC1E:";
    private static final String PLAIN_PREFIX = "CC1P:";
    private static final String BACKUP_SEP = ";";

    private final PlayerStore accounts;
    private final Logger logger;
    private final Path dataFile;
    private final boolean encrypt;
    private final Crypto crypto;
    private final AuthDatabase database;

    private final Map<UUID, Binding> byUuid = new ConcurrentHashMap<>();
    private final AtomicBoolean dirty = new AtomicBoolean(false);
    private boolean loadFailed;

    public TwoFactorStore(Path dataFolder, PlayerStore accounts, Logger logger, boolean encrypt, Crypto crypto) {
        this(dataFolder, accounts, logger, encrypt, crypto, null);
    }

    public TwoFactorStore(Path dataFolder, PlayerStore accounts, Logger logger, boolean encrypt, Crypto crypto,
                          AuthDatabase database) {
        this.accounts = accounts;
        this.logger = logger;
        this.dataFile = dataFolder.resolve("data").resolve("twofa.db");
        this.encrypt = encrypt;
        this.crypto = crypto;
        this.database = database;
    }

    public void load() {
        try {
            if (database != null) {
                for (Binding binding : StorageCodec.bindings(database.read(AuthDatabase.Table.BINDINGS))) {
                    if (byUuid.putIfAbsent(binding.uuid(), binding) != null) throw new IllegalArgumentException("Duplicate 2FA record");
                }
                logger.info("Загружено привязок 2FA: " + byUuid.size());
                return;
            }
            Files.createDirectories(dataFile.getParent());
            if (!Files.exists(dataFile)) {
                return;
            }
            String content = Files.readString(dataFile, StandardCharsets.UTF_8);
            if (content.isEmpty()) {
                throw new IllegalArgumentException("Empty 2FA database");
            }
            if (content.startsWith(ENCRYPTED_PREFIX)) {
                if (crypto == null) {
                    throw new IllegalStateException("Encrypted 2FA bindings require the original storage key");
                }
                content = crypto.decrypt(content.substring(ENCRYPTED_PREFIX.length()));
            } else if (content.startsWith(PLAIN_PREFIX)) {
                content = content.substring(PLAIN_PREFIX.length());
            }
            parse(content);
            logger.info("Загружено привязок 2FA: " + byUuid.size());
        } catch (Exception exception) {
            loadFailed = true;
            throw new IllegalStateException("Cannot load 2FA bindings; authentication must remain blocked", exception);
        }
    }

    private void parse(String content) {
        for (String line : content.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            String[] parts = trimmed.split("\t", -1);
            if (parts.length < 6) {
                throw new IllegalArgumentException("Malformed 2FA record");
            }
            try {
                UUID uuid = UUID.fromString(parts[0]);
                if (!parts[1].equals("true") && !parts[1].equals("false")) {
                    throw new IllegalArgumentException("Invalid enabled flag");
                }
                boolean enabled = Boolean.parseBoolean(parts[1]);
                Provider provider = Provider.parse(parts[2]).orElseThrow();
                String messengerId = parts[3].isEmpty() ? null : parts[3];
                if (messengerId == null || !messengerId.matches("[1-9][0-9]{0,24}")) {
                    throw new IllegalArgumentException("Invalid messenger identity");
                }
                List<String> backup = new ArrayList<>();
                if (!parts[4].isEmpty()) {
                    for (String h : parts[4].split(BACKUP_SEP)) {
                        if (!h.isBlank()) {
                            backup.add(h);
                        }
                    }
                }
                long createdAt = Long.parseLong(parts[5]);
                byUuid.put(uuid, new Binding(uuid, enabled, provider, messengerId, backup, createdAt));
            } catch (RuntimeException exception) {
                throw new IllegalArgumentException("Malformed 2FA record", exception);
            }
        }
    }

    public synchronized void save() {
        if (loadFailed) {
            return;
        }
        if (!dirty.getAndSet(false)) {
            return;
        }
        if (database != null) {
            try {
                database.replace(AuthDatabase.Table.BINDINGS, byUuid.values().stream().map(StorageCodec::binding).toList());
            } catch (RuntimeException failure) {
                dirty.set(true);
                throw failure;
            }
            return;
        }
        StringBuilder sb = new StringBuilder(byUuid.size() * 128);
        for (Binding b : byUuid.values()) {
            sb.append(b.uuid()).append('\t')
                    .append(b.enabled()).append('\t')
                    .append(b.provider() == null ? "" : b.provider().name()).append('\t')
                    .append(b.messengerId() == null ? "" : b.messengerId()).append('\t')
                    .append(String.join(BACKUP_SEP, b.backupHashes())).append('\t')
                    .append(b.createdAt()).append('\n');
        }
        try {
            Files.createDirectories(dataFile.getParent());
            boolean doEncrypt = encrypt;
            if (doEncrypt && crypto == null) {
                throw new IllegalStateException("Storage encryption key unavailable");
            }
            String payload = doEncrypt ? ENCRYPTED_PREFIX + crypto.encrypt(sb.toString()) : PLAIN_PREFIX + sb;
            AtomicFile.write(dataFile, payload);
        } catch (Exception exception) {
            dirty.set(true);
            logger.severe("Не удалось сохранить базу 2FA: " + exception);
        }
    }

    public Optional<Binding> binding(UUID uuid) {
        return Optional.ofNullable(byUuid.get(uuid));
    }

    public boolean isActive(UUID uuid) {
        Binding b = byUuid.get(uuid);
        return b != null && b.enabled() && b.linked();
    }

    public boolean isLinked(UUID uuid) {
        Binding b = byUuid.get(uuid);
        return b != null && b.linked();
    }

    public Optional<Binding> byMessenger(Provider provider, String messengerId) {
        return byUuid.values().stream()
                .filter(b -> b.provider() == provider && messengerId.equals(b.messengerId()))
                .findFirst();
    }

    public List<String> bind(UUID uuid, Provider provider, String messengerId, int backupCount) {
        return bind(uuid, provider, messengerId, backupCount, () -> true);
    }

    public List<String> bind(UUID uuid, Provider provider, String messengerId, int backupCount,
                             java.util.function.BooleanSupplier valid) {
        if (provider == null || messengerId == null || !messengerId.matches("[1-9][0-9]{0,24}")) {
            throw new IllegalArgumentException("Invalid messenger identity");
        }
        if (!valid.getAsBoolean()) return null;
        if (byMessenger(provider, messengerId).filter(other -> !other.uuid().equals(uuid)).isPresent()) {
            throw new IllegalArgumentException("Messenger already belongs to another account");
        }

        List<String> plain = new ArrayList<>(backupCount);
        List<String> hashes = new ArrayList<>(backupCount);
        for (int i = 0; i < backupCount; i++) {
            String code = BackupCodes.generate();
            plain.add(code);
            char[] secret = code.toCharArray();
            try { hashes.add(accounts.hash(secret)); }
            finally { java.util.Arrays.fill(secret, '\0'); }
        }
        synchronized (this) {
            if (!valid.getAsBoolean()) return null;
            if (isLinked(uuid) || byMessenger(provider, messengerId).filter(other -> !other.uuid().equals(uuid)).isPresent()) {
                throw new IllegalArgumentException("Account or messenger already linked");
            }
            commit(new Binding(uuid, true, provider, messengerId, hashes, System.currentTimeMillis()));
        }
        return plain;
    }

    public Optional<List<String>> regenerateBackup(UUID uuid, int backupCount) {
        Binding b = byUuid.get(uuid);
        if (b == null || !b.linked()) {
            return Optional.empty();
        }
        List<String> plain = new ArrayList<>(backupCount);
        List<String> hashes = new ArrayList<>(backupCount);
        for (int i = 0; i < backupCount; i++) {
            String code = BackupCodes.generate();
            plain.add(code);
            char[] secret = code.toCharArray();
            try { hashes.add(accounts.hash(secret)); }
            finally { java.util.Arrays.fill(secret, '\0'); }
        }
        synchronized (this) {
            if (byUuid.get(uuid) != b) return Optional.empty();
            commit(b.withBackup(hashes));
        }
        return Optional.of(plain);
    }

    public synchronized void setEnabled(UUID uuid, boolean enabled) {
        Binding b = byUuid.get(uuid);
        if (b != null && b.enabled() != enabled) {
            commit(b.withEnabled(enabled));
        }
    }

    public synchronized void unbind(UUID uuid) {
        if (database != null) database.delete(AuthDatabase.Table.BINDINGS, uuid);
        if (byUuid.remove(uuid) != null) {
            if (database == null) dirty.set(true);
        }
    }

    public int backupLeft(UUID uuid) {
        Binding b = byUuid.get(uuid);
        return b == null ? 0 : b.backupHashes().size();
    }

    public boolean consumeBackup(UUID uuid, String rawCode) {
        Binding b = byUuid.get(uuid);
        if (b == null || b.backupHashes().isEmpty()) {
            return false;
        }
        String normalized = BackupCodes.normalize(rawCode);
        if (!normalized.matches("[A-Z2-9]{8}")) {
            return false;
        }
        char[] chars = (normalized.substring(0, 4) + "-" + normalized.substring(4)).toCharArray();
        try {
            for (String hash : b.backupHashes()) {
                if (accounts.verify(chars, hash)) {
                    synchronized (this) {
                        Binding current = byUuid.get(uuid);
                        if (current != b) return false;
                        List<String> left = new ArrayList<>(b.backupHashes());
                        left.remove(hash);
                        commit(b.withBackup(left));
                        return true;
                    }
                }
            }
            return false;
        } finally {
            java.util.Arrays.fill(chars, '\0');
        }
    }

    private void commit(Binding binding) {
        if (database != null) database.write(AuthDatabase.Table.BINDINGS, binding.uuid(), StorageCodec.binding(binding));
        byUuid.put(binding.uuid(), binding);
        if (database == null) dirty.set(true);
    }
}
