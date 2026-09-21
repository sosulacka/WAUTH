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

import at.favre.lib.crypto.bcrypt.BCrypt;
import mc.t1rei.wauth.core.Crypto;
import mc.t1rei.wauth.core.AtomicFile;
import mc.t1rei.wauth.storage.AuthDatabase;
import mc.t1rei.wauth.storage.StorageCodec;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Logger;

public final class PlayerStore {

    public record Account(UUID uuid, String name, String hash, long registeredAt, long lastLoginAt, String lastIp,
                          boolean locked) {

        public Account(UUID uuid, String name, String hash, long registeredAt, long lastLoginAt, String lastIp) {
            this(uuid, name, hash, registeredAt, lastLoginAt, lastIp, false);
        }

        Account withLogin(String ip, long at) {
            return new Account(uuid, name, hash, registeredAt, at, ip, locked);
        }

        Account withHash(String newHash) {
            return new Account(uuid, name, newHash, registeredAt, lastLoginAt, lastIp, locked);
        }
    }

    private static final String ENCRYPTED_PREFIX = "CC1E:";
    private static final String PLAIN_PREFIX = "CC1P:";

    private final AuthConfig config;
    private final Logger logger;
    private final Path dataFile;
    private final AuthDatabase database;
    private final Map<UUID, Account> byUuid = new ConcurrentHashMap<>();
    private final Map<String, java.util.Set<UUID>> byName = new ConcurrentHashMap<>();
    private final AtomicBoolean dirty = new AtomicBoolean(false);
    private final java.util.Set<UUID> loginUpdates = ConcurrentHashMap.newKeySet();

    private Crypto crypto;
    private boolean loadFailed;

    public PlayerStore(Path dataFolder, AuthConfig config, Logger logger) {
        this(dataFolder, config, logger, null);
    }

    public PlayerStore(Path dataFolder, AuthConfig config, Logger logger, AuthDatabase database) {
        this.config = config;
        this.logger = logger;
        this.dataFile = dataFolder.resolve("data").resolve("accounts.db");
        this.database = database;
    }

    public void useCrypto(Crypto crypto) {
        this.crypto = crypto;
    }

    public void load() {
        try {
            if (database != null) {
                for (Account account : StorageCodec.accounts(database.read(AuthDatabase.Table.ACCOUNTS))) putLoaded(account);
                logger.info("Загружено аккаунтов: " + byUuid.size());
                return;
            }
            Files.createDirectories(dataFile.getParent());
            if (!Files.exists(dataFile)) {
                return;
            }
            String content = Files.readString(dataFile, StandardCharsets.UTF_8);
            if (content.isEmpty()) {
                throw new IllegalArgumentException("Empty account database");
            }
            if (content.startsWith(ENCRYPTED_PREFIX)) {
                if (crypto == null) {
                    throw new IllegalStateException("Encrypted accounts require the original storage key");
                }
                content = crypto.decrypt(content.substring(ENCRYPTED_PREFIX.length()));
            } else if (content.startsWith(PLAIN_PREFIX)) {
                content = content.substring(PLAIN_PREFIX.length());
            }
            parse(content);
            logger.info("Загружено аккаунтов: " + byUuid.size());
        } catch (Exception exception) {
            loadFailed = true;
            throw new IllegalStateException("Cannot load accounts; authentication must remain blocked", exception);
        }
    }

    private void parse(String content) {
        for (String line : content.split("\n")) {
            String trimmed = line.endsWith("\r") ? line.substring(0, line.length() - 1) : line;
            if (trimmed.isBlank()) {
                continue;
            }
            String[] parts = trimmed.split("\t", -1);
            if (parts.length < 6 || parts.length > 7) {
                throw new IllegalArgumentException("Malformed account record");
            }
            try {
                Account account = StorageCodec.accounts(java.util.List.of(trimmed)).getFirst();
                putLoaded(account);
            } catch (RuntimeException exception) {
                throw new IllegalArgumentException("Malformed account record", exception);
            }
        }
    }

    private void putLoaded(Account account) {
        if (byUuid.putIfAbsent(account.uuid(), account) != null) {
            throw new IllegalArgumentException("Duplicate account record");
        }
        addName(account);
    }

    private void addName(Account account) {
        byName.compute(account.name().toLowerCase(Locale.ROOT), (key, existing) -> {
            var ids = existing == null ? new java.util.HashSet<UUID>() : new java.util.HashSet<>(existing);
            ids.add(account.uuid());
            return java.util.Set.copyOf(ids);
        });
    }

    private void removeName(Account account) {
        byName.computeIfPresent(account.name().toLowerCase(Locale.ROOT), (key, existing) -> {
            var ids = new java.util.HashSet<>(existing);
            ids.remove(account.uuid());
            return ids.isEmpty() ? null : java.util.Set.copyOf(ids);
        });
    }

    public synchronized void save() {
        if (loadFailed) {
            return;
        }
        if (!dirty.getAndSet(false)) {
            return;
        }
        if (database != null) {
            java.util.List<UUID> changed = new java.util.ArrayList<>();
            for (UUID uuid : loginUpdates) {
                if (loginUpdates.remove(uuid)) changed.add(uuid);
            }
            try {
                database.writeBatch(AuthDatabase.Table.ACCOUNTS, changed.stream().map(byUuid::get)
                        .filter(java.util.Objects::nonNull).map(StorageCodec::account).toList());
            } catch (RuntimeException failure) {
                loginUpdates.addAll(changed);
                dirty.set(true);
                throw failure;
            }
            return;
        }
        StringBuilder sb = new StringBuilder(byUuid.size() * 96);
        for (Account a : byUuid.values()) {
            sb.append(StorageCodec.account(a)).append('\n');
        }
        try {
            Files.createDirectories(dataFile.getParent());
            boolean encrypt = config != null && config.encryptStorage();
            if (encrypt && crypto == null) {
                throw new IllegalStateException("Storage encryption key unavailable");
            }
            String payload = encrypt
                    ? ENCRYPTED_PREFIX + crypto.encrypt(sb.toString())
                    : PLAIN_PREFIX + sb;
            AtomicFile.write(dataFile, payload);
        } catch (Exception exception) {
            dirty.set(true);
            throw new IllegalStateException("Cannot save accounts", exception);
        }
    }

    public String hash(char[] password) {
        return BCrypt.withDefaults().hashToString(config == null ? 12 : config.bcryptCost(), password);
    }

    public boolean verify(char[] password, String hash) {
        if (password == null || StandardCharsets.UTF_8.encode(java.nio.CharBuffer.wrap(password)).remaining() > 72) {
            return false;
        }
        try {
            return hash != null && BCrypt.verifyer().verify(password, hash.toCharArray()).verified;
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }

    public boolean isRegistered(UUID uuid) {
        return byUuid.containsKey(uuid);
    }

    public Optional<Account> byUuid(UUID uuid) {
        return Optional.ofNullable(byUuid.get(uuid));
    }

    public Optional<Account> byName(String name) {
        var ids = byName.get(name.toLowerCase(Locale.ROOT));
        return ids == null || ids.size() != 1 ? Optional.empty() : byUuid(ids.iterator().next());
    }

    public java.util.List<UUID> matchingIds(String name) {
        return byName.getOrDefault(name.toLowerCase(Locale.ROOT), java.util.Set.of()).stream().sorted().toList();
    }

    public Optional<Account> byTarget(String target) {
        if (target.matches("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")) {
            return byUuid(UUID.fromString(target));
        }
        return byName(target);
    }

    public synchronized void put(Account account) {
        var owners = byName.get(account.name().toLowerCase(Locale.ROOT));
        Account current = byUuid.get(account.uuid());
        boolean keepsName = current != null && current.name().equalsIgnoreCase(account.name());
        if (!keepsName && owners != null && owners.stream().anyMatch(id -> !id.equals(account.uuid()))) {
            throw new IllegalArgumentException("Account name already owned");
        }
        if (database != null) database.write(AuthDatabase.Table.ACCOUNTS, account.uuid(), StorageCodec.account(account));
        Account previous = byUuid.put(account.uuid(), account);
        if (previous != null && !previous.name().equalsIgnoreCase(account.name())) {
            removeName(previous);
        }
        addName(account);
        if (database == null) dirty.set(true);
    }

    public synchronized boolean register(Account account) {
        if (byUuid.containsKey(account.uuid()) || byName.containsKey(account.name().toLowerCase(Locale.ROOT))) return false;
        put(account);
        return true;
    }

    public synchronized boolean updateHash(Account account, String newHash) {
        Account current = byUuid.get(account.uuid());
        if (current == null || !current.hash().equals(account.hash())) return false;
        put(current.withHash(newHash));
        return true;
    }

    public synchronized void markLogin(Account account, String ip) {
        byUuid.computeIfPresent(account.uuid(), (uuid, current) -> current.withLogin(ip, System.currentTimeMillis()));
        if (database != null) loginUpdates.add(account.uuid());
        dirty.set(true);
    }

    public boolean isLocked(UUID uuid) {
        return byUuid(uuid).map(Account::locked).orElse(false);
    }

    public synchronized boolean setLocked(Account expected, boolean locked) {
        Account current = byUuid.get(expected.uuid());
        if (current == null || !current.hash().equals(expected.hash()) || current.locked() != expected.locked()) return false;
        put(new Account(current.uuid(), current.name(), current.hash(), current.registeredAt(),
                current.lastLoginAt(), current.lastIp(), locked));
        return true;
    }

    public synchronized void remove(UUID uuid) {
        if (database != null) database.delete(AuthDatabase.Table.ACCOUNTS, uuid);
        Account removed = byUuid.remove(uuid);
        if (removed != null) {
            removeName(removed);
            if (database == null) dirty.set(true);
        }
    }

    public java.util.List<String> knownNames() {
        return byUuid.values().stream().map(Account::name).distinct().sorted().toList();
    }
}
