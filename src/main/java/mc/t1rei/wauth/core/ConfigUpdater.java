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

import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.YamlConfiguration;

import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

public final class ConfigUpdater {
    private ConfigUpdater() {}

    public record Result(YamlConfiguration yaml, List<String> added, Path backup) {}

    public static Result load(Path file, Reader defaultsReader) throws Exception {
        String original = Files.readString(file);
        YamlConfiguration current = parse(original);
        YamlConfiguration defaults = new YamlConfiguration();
        defaults.options().parseComments(true);
        defaults.load(defaultsReader);
        List<String> added = new ArrayList<>();
        merge(current, defaults, "", added);
        validate(current);
        Path backup = null;
        if (!added.isEmpty()) {
            String updated = current.saveToString();
            parse(updated);
            if (!Files.readString(file).equals(original)) throw new IOException("Configuration changed during upgrade");
            backup = file.resolveSibling(file.getFileName() + ".before-update-" + UUID.randomUUID() + ".bak");
            AtomicFile.write(backup, original);
            AtomicFile.write(file, updated);
        }
        return new Result(current, List.copyOf(added), backup);
    }

    private static YamlConfiguration parse(String text) throws Exception {
        YamlConfiguration yaml = new YamlConfiguration();
        yaml.options().parseComments(true);
        yaml.loadFromString(text);
        return yaml;
    }

    private static void merge(YamlConfiguration target, ConfigurationSection defaults, String prefix, List<String> added) {
        for (String key : defaults.getKeys(false)) {
            String path = prefix + key;
            Object expected = defaults.get(key);
            Object actual = target.get(path);
            if (expected instanceof ConfigurationSection section) {
                if (actual != null && !(actual instanceof ConfigurationSection)) invalid(path, "section");
                merge(target, section, path + ".", added);
            } else if (actual == null) {
                target.set(path, expected);
                target.setComments(path, defaults.getComments(key));
                target.setInlineComments(path, defaults.getInlineComments(key));
                added.add(path);
            } else if (path.startsWith("messages.")) {
                if (!(actual instanceof String) && !strings(actual)) invalid(path, "text or list of text");
            } else if (expected instanceof Boolean) {
                if (!(actual instanceof Boolean)) invalid(path, "boolean (true/false)");
            } else if (expected instanceof Number) {
                if (!(actual instanceof Number n) || !Double.isFinite(n.doubleValue())
                        || n.doubleValue() != n.intValue()) invalid(path, "integer");
            } else if (expected instanceof List<?>) {
                if (!strings(actual)) invalid(path, "list of text");
            } else if (isDuration(path)) {
                if (!(actual instanceof String || actual instanceof Number) || Text.parseDuration(actual, -1) < 0
                        || (actual instanceof Number n && (!Double.isFinite(n.doubleValue()) || n.doubleValue() < 0))) {
                    invalid(path, "duration such as 45s or 2m");
                }
            } else if (!(actual instanceof String)) {
                invalid(path, "text");
            }
        }
    }

    private static boolean strings(Object value) {
        return value instanceof List<?> list && list.stream().allMatch(String.class::isInstance);
    }

    private static boolean isDuration(String path) {
        return path.endsWith("timeout") || path.endsWith("duration") || path.endsWith("interval") || path.endsWith(".window");
    }

    private static void validate(YamlConfiguration yaml) {
        if (yaml.getInt("auth.password.max-length") < yaml.getInt("auth.password.min-length")) {
            invalid("auth.password.max-length", "value at least auth.password.min-length");
        }
        try { Pattern.compile(yaml.getString("auth.password.pattern", "")); }
        catch (java.util.regex.PatternSyntaxException invalid) { invalid("auth.password.pattern", "valid regular expression"); }
        String punishment = yaml.getString("auth.punishment.type", "KICK");
        if (!punishment.equalsIgnoreCase("KICK") && !punishment.equalsIgnoreCase("BAN")) invalid("auth.punishment.type", "KICK or BAN");
    }

    private static void invalid(String path, String expected) {
        throw new IllegalArgumentException("Invalid config key " + path + "; expected " + expected);
    }
}
