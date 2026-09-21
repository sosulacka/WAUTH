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

import mc.t1rei.wauth.core.ConfigUpdater;
import mc.t1rei.wauth.core.Crypto;
import mc.t1rei.wauth.storage.AuthDatabase;
import mc.t1rei.wauth.twofa.TwoFactorStore;
import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.YamlConfiguration;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.logging.Logger;

public final class LocalUpgradeCheck {
    public static void main(String[] args) throws Exception {
        Path source = Path.of(args[0]);
        Path config = Path.of(args[1]);
        Path copy = Files.createTempDirectory(Path.of("build"), "server-upgrade-");
        Files.createDirectories(copy.resolve("data"));
        for (String name : List.of("accounts.db", "twofa.db", "store.key")) {
            Files.copy(source.resolve(name), copy.resolve("data").resolve(name));
        }
        Logger log = Logger.getLogger("local-upgrade");
        Crypto crypto = Crypto.load(copy.resolve("data/store.key"), log);
        List<String> originalAccounts = rows(source.resolve("accounts.db"), crypto);
        List<String> originalBindings = rows(source.resolve("twofa.db"), crypto);
        try (var db = new AuthDatabase(copy, true, crypto, true, log)) {
            db.open();
            checkRows(db, originalAccounts, originalBindings);
            PlayerStore accounts = new PlayerStore(copy, null, log, db);
            accounts.load();
            TwoFactorStore bindings = new TwoFactorStore(copy, accounts, log, true, crypto, db);
            bindings.load();
            for (String row : originalAccounts) {
                var fields = row.split("\t", -1);
                if (!accounts.byTarget(fields[0]).orElseThrow().hash().equals(fields[2])) throw new AssertionError("Password changed");
            }
        }
        try (var db = new AuthDatabase(copy, true, crypto, true, log)) {
            db.open();
            checkRows(db, originalAccounts, originalBindings);
        }
        if (Files.exists(copy.resolve("data/accounts.db")) || Files.exists(copy.resolve("data/twofa.db"))) {
            throw new AssertionError("Legacy cleanup not completed");
        }
        try (var paths = Files.list(copy.resolve("data/legacy-backup"))) {
            Path backup = paths.findFirst().orElseThrow();
            for (String name : List.of("accounts.db", "twofa.db", "store.key")) {
                if (Files.mismatch(source.resolve(name), backup.resolve(name)) != -1) throw new AssertionError("Backup mismatch");
            }
        }
        YamlConfiguration original = new YamlConfiguration();
        original.load(config.toFile());
        ConfigUpdater.Result result;
        try (var reader = Files.newBufferedReader(Path.of("src/main/resources/config.yml"))) {
            result = ConfigUpdater.load(config, reader);
        }
        for (String key : original.getKeys(true)) {
            if (original.get(key) instanceof ConfigurationSection) continue;
            if (!Objects.equals(original.get(key), result.yaml().get(key))) throw new AssertionError("Setting changed: " + key);
        }
        System.out.println("Verified archive migration and reopen: " + originalAccounts.size() + " accounts, " + originalBindings.size() + " bindings; every field preserved");
        System.out.println("Verified byte-identical legacy backups and post-import cleanup");
        System.out.println("Config updated; existing values preserved; weak-list size: " + result.yaml().getStringList("auth.password.weak-list").size());
        System.out.println("Added keys: " + String.join(", ", result.added()));
        System.out.println("Config backup: " + result.backup());
        System.out.println("Local migrated test copy: " + copy);
    }

    private static List<String> rows(Path file, Crypto crypto) throws Exception {
        String text = Files.readString(file);
        if (text.startsWith("CC1E:")) text = crypto.decrypt(text.substring(5));
        else if (text.startsWith("CC1P:")) text = text.substring(5);
        return text.lines().filter(line -> !line.isBlank()).toList();
    }

    private static void checkRows(AuthDatabase db, List<String> accounts, List<String> bindings) {
        if (!new HashSet<>(accounts).equals(new HashSet<>(db.read(AuthDatabase.Table.ACCOUNTS)))
                || !new HashSet<>(bindings).equals(new HashSet<>(db.read(AuthDatabase.Table.BINDINGS)))) {
            throw new AssertionError("Migrated records differ from source");
        }
    }
}
