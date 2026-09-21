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

import net.kyori.adventure.text.Component;
import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

public final class ConfigFile {

    private final JavaPlugin plugin;
    private final String name;
    private final File file;

    private YamlConfiguration yaml;
    private Supplier<String> prefixSource = () -> "";

    public ConfigFile(JavaPlugin plugin, String name) {
        this.plugin = plugin;
        this.name = name;
        this.file = new File(plugin.getDataFolder(), name);
        reload();
    }

    public ConfigFile prefixSource(Supplier<String> supplier) {
        this.prefixSource = supplier;
        return this;
    }

    public void reload() {
        if (!file.exists()) {
            plugin.saveResource(name, false);
        }
        InputStream resource = plugin.getResource(name);
        if (resource == null) {
            throw new IllegalStateException("Missing bundled defaults for " + name);
        }
        try (Reader reader = new InputStreamReader(resource, StandardCharsets.UTF_8)) {
            ConfigUpdater.Result result = ConfigUpdater.load(file.toPath(), reader);
            yaml = result.yaml();
            if (!result.added().isEmpty()) {
                plugin.getLogger().info("Updated " + name + "; added keys: " + String.join(", ", result.added())
                        + "; previous file: " + result.backup().getFileName());
            }
        } catch (Exception exception) {
            String detail = exception instanceof IllegalArgumentException
                    && exception.getMessage() != null && exception.getMessage().startsWith("Invalid config key ")
                    ? exception.getMessage() : "invalid YAML or read/write failure (" + exception.getClass().getSimpleName() + ")";
            throw new IllegalStateException("Cannot load " + name + ": " + detail + "; keeping the previous configuration");
        }
    }
    public String name() {
        return name;
    }

    public YamlConfiguration yaml() {
        return yaml;
    }

    public boolean bool(String path, boolean fallback) {
        return yaml.getBoolean(path, fallback);
    }

    public int integer(String path, int fallback) {
        return yaml.getInt(path, fallback);
    }

    public double decimal(String path, double fallback) {
        return yaml.getDouble(path, fallback);
    }

    public String string(String path, String fallback) {
        String value = yaml.getString(path);
        return value == null ? fallback : value;
    }

    public List<String> list(String path) {
        return yaml.getStringList(path);
    }

    public ConfigurationSection section(String path) {
        return yaml.getConfigurationSection(path);
    }

    public long duration(String path, long fallbackMillis) {
        return Text.parseDuration(yaml.get(path), fallbackMillis);
    }

    public String raw(String key, String... placeholders) {
        return render(yaml.get("messages." + key), "messages." + key, placeholders);
    }

    public String rawAt(String path, String... placeholders) {
        return render(yaml.get(path), path, placeholders);
    }

    public Component message(String key, String... placeholders) {
        return Text.color(raw(key, placeholders));
    }

    public Component messageAt(String path, String... placeholders) {
        return Text.color(rawAt(path, placeholders));
    }
    private String render(Object value, String path, String... placeholders) {
        String joined;
        if (value instanceof List<?> lines) {
            List<String> parts = new ArrayList<>(lines.size());
            for (Object line : lines) {
                parts.add(String.valueOf(line));
            }
            joined = String.join("\n", parts);
        } else if (value == null) {
            joined = "&cОтсутствует значение " + path + " в " + name;
        } else {
            joined = String.valueOf(value);
        }
        return Text.replace(joined.replace("{prefix}", prefixSource.get()), placeholders);
    }
}
