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

import mc.t1rei.wauth.core.AtomicFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

final class LegacyFiles {
    record Entry(String name, String digest, String backup) {}

    static List<Entry> backup(Path directory) throws Exception {
        if (!Files.exists(directory.resolve("accounts.db")) && !Files.exists(directory.resolve("twofa.db"))) return List.of();
        Path backup = directory.resolve("legacy-backup").resolve(UUID.randomUUID().toString());
        List<Entry> entries = new ArrayList<>();
        for (String name : List.of("accounts.db", "twofa.db", "store.key")) {
            Path source = directory.resolve(name);
            if (!Files.exists(source)) continue;
            String original = Files.readString(source);
            Path target = backup.resolve(name);
            AtomicFile.write(target, original);
            String hash = digest(source);
            if (!hash.equals(digest(target))) throw new IllegalStateException("Legacy file changed during backup: " + name);
            entries.add(new Entry(name, hash, directory.relativize(target).toString().replace('\\', '/')));
        }
        return List.copyOf(entries);
    }

    static void verify(Path directory, List<Entry> entries) throws Exception {
        for (Entry entry : entries) {
            if (!digest(directory.resolve(entry.name())).equals(entry.digest())) {
                throw new IllegalStateException("Legacy file changed during import: " + entry.name());
            }
        }
    }

    static void removeImported(Path directory, Entry entry) throws Exception {
        if (!List.of("accounts.db", "twofa.db").contains(entry.name())) return;
        Path source = directory.resolve(entry.name());
        if (!Files.exists(source)) return;
        Path backupRoot = directory.resolve("legacy-backup").toAbsolutePath().normalize();
        Path backup = directory.resolve(entry.backup()).toAbsolutePath().normalize();
        if (!backup.startsWith(backupRoot) || !Files.isRegularFile(backup)
                || !backup.toRealPath().startsWith(backupRoot.toRealPath())
                || !digest(backup).equals(entry.digest()) || !digest(source).equals(entry.digest())) {
            throw new IllegalStateException("Legacy backup/source mismatch: " + entry.name());
        }
        Files.delete(source);
    }

    private static String digest(Path path) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));
    }
}
