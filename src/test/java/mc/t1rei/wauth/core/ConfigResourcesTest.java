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

import org.bukkit.configuration.file.YamlConfiguration;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConfigResourcesTest {

    private static final Path RESOURCES = Path.of("src", "main", "resources");
    private static final Path SOURCES = Path.of("src", "main", "java", "mc", "t1rei", "wauth");

    private static final Pattern MESSAGE_CALL =
            Pattern.compile("(?:rawMessage|message)\\(\"([a-z0-9\\-]+)\"\\s*[,)]");

    private final Map<String, YamlConfiguration> loaded = new HashMap<>();

    private YamlConfiguration yaml(String name) {
        return loaded.computeIfAbsent(name,
                key -> YamlConfiguration.loadConfiguration(RESOURCES.resolve(key).toFile()));
    }

    private void requireAll(String file, List<String> keys) {
        YamlConfiguration yaml = yaml(file);
        for (String key : keys) {
            assertTrue(yaml.contains(key), file + " не содержит ключ " + key);
        }
    }

    @Test
    void configContainsEverySetting() {
        requireAll("config.yml", List.of(
                "security.hide-passwords-in-console",
                "storage.encrypt", "storage.bcrypt-cost", "storage.save-interval",
                "auth.timeout", "auth.max-attempts", "auth.reminder-interval", "auth.show-actionbar",
                "auth.password.min-length", "auth.password.max-length", "auth.password.pattern",
                "auth.password.forbid-name", "auth.password.reject-weak", "auth.password.weak-list",
                "auth.freeze.block-movement", "auth.freeze.block-camera", "auth.freeze.block-jump",
                "auth.freeze.block-sprint", "auth.freeze.block-interaction", "auth.freeze.block-chat",
                "auth.freeze.invulnerable", "auth.freeze.no-push", "auth.freeze.blindness",
                "auth.punishment.type", "auth.punishment.ban-duration",
                "auth.session.enabled", "auth.session.duration", "auth.session.require-same-ip",
                "auth.allowed-commands",
                "confirmation.enabled", "confirmation.timeout",
                "confirmation.require-for.changepass", "confirmation.require-for.forcechangepass",
                "confirmation.require-for.forceresetpass",
                "messages.prefix", "messages.players-only", "messages.no-permission",
                "messages.reload-success"));
        assertFalse(yaml("config.yml").getStringList("auth.allowed-commands").isEmpty());
    }

    @Test
    void everyOwnCommandIsAllowedBeforeLogin() {
        List<String> allowed = yaml("config.yml").getStringList("auth.allowed-commands");
        for (String label : List.of("register", "reg", "login", "l", "wauth", "wa")) {
            assertTrue(allowed.contains(label), "auth.allowed-commands не содержит " + label);
        }
    }

    @Test
    void rejectsTenWeakPasswords() {
        List<String> weak = yaml("config.yml").getStringList("auth.password.weak-list");
        assertTrue(weak.size() >= 10, "Ожидалось не менее 10 простых паролей, найдено " + weak.size());
        assertTrue(weak.contains("123456"));
    }

    @Test
    void everyMessageKeyReferencedInCodeExists() throws IOException {
        Set<String> missing = new TreeSet<>();
        try (Stream<Path> files = Files.walk(SOURCES)) {
            for (Path file : files.filter(path -> path.toString().endsWith(".java")).toList()) {
                Matcher matcher = MESSAGE_CALL.matcher(Files.readString(file, StandardCharsets.UTF_8));
                while (matcher.find()) {
                    String path = "messages." + matcher.group(1);
                    if (!yaml("config.yml").contains(path)) {
                        missing.add(path);
                    }
                }
            }
        }
        assertTrue(missing.isEmpty(), "Отсутствуют сообщения: " + missing);
    }

    @Test
    void pluginYmlDeclaresEveryCommandAndPermission() {
        YamlConfiguration yaml = YamlConfiguration.loadConfiguration(RESOURCES.resolve("plugin.yml").toFile());
        for (String command : List.of("register", "login", "changepass",
                "forcechangepass", "forceresetpass", "wauth")) {
            assertTrue(yaml.contains("commands." + command), "plugin.yml не объявляет команду " + command);
        }
        assertTrue(yaml.getStringList("commands.register.aliases").contains("reg"));
        assertTrue(yaml.getStringList("commands.login.aliases").contains("l"));
        assertTrue(yaml.getStringList("commands.wauth.aliases").contains("wa"));
        for (String permission : List.of("wauth.changepass", "wauth.forcechangepass",
                "wauth.forceresetpass", "wauth.reload", "wauth.admin")) {
            assertTrue(yaml.contains("permissions." + permission),
                    "plugin.yml не объявляет право " + permission);
        }
    }
}
