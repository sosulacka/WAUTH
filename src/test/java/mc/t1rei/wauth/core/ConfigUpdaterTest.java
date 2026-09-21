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
import static org.junit.jupiter.api.Assertions.*;

class ConfigUpdaterTest {
    @TempDir Path dir;

    ConfigUpdater.Result update(Path file) throws Exception {
        try (var reader = Files.newBufferedReader(Path.of("src/main/resources/config.yml"))) {
            return ConfigUpdater.load(file, reader);
        }
    }

    @Test void fillsMissingKeysAndPreservesValuesSecretsListsAndUnknownSettings() throws Exception {
        Path file = dir.resolve("config.yml");
        String original = "# custom server settings\ntwofa:\n  enabled: true\n  telegram:\n    enabled: true\n    token: 'private-test-token'\n"
                + "auth:\n  password:\n    weak-list: ['custom', 'only-mine']\n  timeout: 90\nmessages:\n  login-success: ['custom text']\ncustom-setting: retained\n";
        Files.writeString(file, original);
        var result = update(file);
        assertFalse(result.added().isEmpty());
        assertEquals(original, Files.readString(result.backup()));
        assertTrue(result.yaml().getBoolean("twofa.enabled"));
        assertEquals("private-test-token", result.yaml().getString("twofa.telegram.token"));
        assertEquals(java.util.List.of("custom", "only-mine"), result.yaml().getStringList("auth.password.weak-list"));
        assertEquals(90, result.yaml().getInt("auth.timeout"));
        assertEquals("retained", result.yaml().getString("custom-setting"));
        assertEquals(java.util.List.of("custom text"), result.yaml().getStringList("messages.login-success"));
        assertTrue(result.yaml().getBoolean("storage.migration.remove-legacy-files"));
        assertTrue(Files.readString(file).contains("# custom server settings"));
        String updated = Files.readString(file);
        assertTrue(update(file).added().isEmpty());
        assertEquals(updated, Files.readString(file));
        try (var files = Files.list(dir)) { assertEquals(2, files.count()); }
    }

    @Test void wrongTypesAndInvalidDurationsDoNotOverwriteServerConfig() throws Exception {
        Path file = dir.resolve("config.yml");
        for (String invalid : new String[]{"twofa: false\n", "twofa:\n  enabled: 'false'\n",
                "auth:\n  timeout: nonsense\n", "auth:\n  password:\n    weak-list: [true]\n",
                "security:\n  workers:\n    threads: 1.5\n", "auth:\n  punishment:\n    type: OTHER\n"}) {
            Files.writeString(file, invalid);
            assertThrows(IllegalArgumentException.class, () -> update(file));
            assertEquals(invalid, Files.readString(file));
        }
        try (var files = Files.list(dir)) { assertEquals(1, files.count()); }
    }

    @Test void malformedYamlIsNeverReplacedWithDefaults() throws Exception {
        Path file = dir.resolve("config.yml");
        String broken = "twofa: [unterminated";
        Files.writeString(file, broken);
        assertThrows(Exception.class, () -> update(file));
        assertEquals(broken, Files.readString(file));
    }

    @Test void acceptsSingleLineAndMultilineMessagesWithoutConvertingThem() throws Exception {
        Path file = dir.resolve("config.yml");
        Files.writeString(file, "messages:\n  join-register: one-line\n  prefix: ''\n");
        assertEquals("one-line", update(file).yaml().getString("messages.join-register"));
    }

    @Test void invalidPasswordPatternOrBoundsAreRejectedBeforeSaving() throws Exception {
        Path file = dir.resolve("config.yml");
        for (String invalid : new String[]{"auth:\n  password:\n    pattern: '['\n",
                "auth:\n  password:\n    min-length: 20\n    max-length: 10\n"}) {
            Files.writeString(file, invalid);
            assertThrows(IllegalArgumentException.class, () -> update(file));
            assertEquals(invalid, Files.readString(file));
        }
    }
}
