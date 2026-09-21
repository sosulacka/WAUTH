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

import mc.t1rei.wauth.core.ConfigFile;
import net.kyori.adventure.text.Component;
import org.bukkit.plugin.java.JavaPlugin;

import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public final class AuthConfig {

    public enum Punishment { KICK, BAN }

    private static final List<String> DEFAULT_WEAK = List.of(
            "123456", "12345678", "1234567890", "password", "qwerty",
            "qwerty123", "111111", "abc123", "iloveyou", "admin");

    private final JavaPlugin plugin;
    private final ConfigFile file;

    private String prefix;
    private boolean hidePasswordsInConsole;

    private boolean encryptStorage;
    private boolean removeLegacyFiles;
    private int bcryptCost;
    private long saveIntervalMillis;

    private long authTimeoutMillis;
    private int maxAttempts;
    private long reminderIntervalMillis;
    private boolean showActionBar;
    private int accountAttemptLimit;
    private int ipAttemptLimit;
    private int registrationIpLimit;
    private long attemptWindowMillis;
    private int cryptoThreads;
    private int cryptoQueueCapacity;

    private int minPasswordLength;
    private int maxPasswordLength;
    private Pattern passwordPattern;
    private boolean forbidNameAsPassword;
    private boolean rejectWeakPasswords;
    private Set<String> weakPasswords;

    private boolean blockMovement;
    private boolean blockCamera;
    private boolean blockJump;
    private boolean blockSprint;
    private boolean blockInteraction;
    private boolean blockChat;
    private boolean invulnerable;
    private boolean noPush;
    private boolean blindness;

    private Punishment punishment;
    private long banDurationMillis;

    private boolean sessionEnabled;
    private long sessionDurationMillis;
    private long sessionTimeoutMillis;
    private boolean sessionRequireSameIp;

    private Set<String> allowedCommands;

    private boolean confirmationEnabled;
    private long confirmationTimeoutMillis;
    private boolean confirmChangePass;
    private boolean confirmForceChangePass;
    private boolean confirmForceResetPass;

    private boolean twoFactorEnabled;
    private boolean twoFactorEnforce;
    private long twoFactorLinkTimeoutMillis;
    private long twoFactorConfirmTimeoutMillis;
    private int twoFactorBackupCount;
    private boolean httpEnabled;
    private boolean httpShareServerPort;
    private boolean httpTunnel;
    private String httpHost;
    private int httpPort;
    private String httpPublicUrl;
    private boolean telegramEnabled;
    private String telegramToken;
    private boolean vkEnabled;
    private String vkToken;
    private long vkGroupId;
    private boolean discordEnabled;
    private String discordToken;

    public AuthConfig(JavaPlugin plugin) {
        this.plugin = plugin;
        this.file = new ConfigFile(plugin, "config.yml").prefixSource(this::prefix);
        reload();
    }

    public void reload() {
        file.reload();

        prefix = file.string("messages.prefix", "");
        hidePasswordsInConsole = file.bool("security.hide-passwords-in-console", true);

        encryptStorage = file.bool("storage.encrypt", true);
        removeLegacyFiles = file.bool("storage.migration.remove-legacy-files", true);
        bcryptCost = Math.clamp(file.integer("storage.bcrypt-cost", 12), 4, 16);
        saveIntervalMillis = file.duration("storage.save-interval", 60_000L);

        authTimeoutMillis = Math.max(1000L, file.duration("auth.timeout", 45_000L));
        maxAttempts = Math.max(0, file.integer("auth.max-attempts", 3));
        reminderIntervalMillis = Math.max(1000L, file.duration("auth.reminder-interval", 10_000L));
        showActionBar = file.bool("auth.show-actionbar", true);
        accountAttemptLimit = Math.clamp(file.integer("security.rate-limit.account-attempts", 10), 1, 1000);
        ipAttemptLimit = Math.clamp(file.integer("security.rate-limit.ip-attempts", 40), 1, 10000);
        registrationIpLimit = Math.clamp(file.integer("security.rate-limit.registrations-per-ip", 5), 1, 1000);
        attemptWindowMillis = Math.clamp(file.duration("security.rate-limit.window", 300_000L), 1000L, 86_400_000L);
        cryptoThreads = Math.clamp(file.integer("security.workers.threads", 2), 1, 8);
        cryptoQueueCapacity = Math.clamp(file.integer("security.workers.queue-capacity", 32), 1, 256);

        minPasswordLength = Math.max(1, file.integer("auth.password.min-length", 6));
        maxPasswordLength = Math.max(minPasswordLength, file.integer("auth.password.max-length", 64));
        passwordPattern = compile(file.string("auth.password.pattern", ""));
        forbidNameAsPassword = file.bool("auth.password.forbid-name", true);
        rejectWeakPasswords = file.bool("auth.password.reject-weak", true);
        weakPasswords = lower(file.list("auth.password.weak-list"), DEFAULT_WEAK);

        blockMovement = file.bool("auth.freeze.block-movement", true);
        blockCamera = file.bool("auth.freeze.block-camera", true);
        blockJump = file.bool("auth.freeze.block-jump", true);
        blockSprint = file.bool("auth.freeze.block-sprint", true);
        blockInteraction = file.bool("auth.freeze.block-interaction", true);
        blockChat = file.bool("auth.freeze.block-chat", true);
        invulnerable = file.bool("auth.freeze.invulnerable", true);
        noPush = file.bool("auth.freeze.no-push", true);
        blindness = file.bool("auth.freeze.blindness", false);

        punishment = parsePunishment(file.string("auth.punishment.type", "KICK"));
        banDurationMillis = Math.max(1000L, file.duration("auth.punishment.ban-duration", 300_000L));

        sessionEnabled = file.bool("auth.session.enabled", true);
        sessionDurationMillis = Math.max(0L, file.duration("auth.session.duration", 600_000L));
        sessionTimeoutMillis = Math.max(0L, file.duration("auth.session.timeout", sessionDurationMillis));
        sessionRequireSameIp = file.bool("auth.session.require-same-ip", true);

        Set<String> commands = new HashSet<>();
        for (String entry : file.list("auth.allowed-commands")) {
            commands.add(entry.toLowerCase(Locale.ROOT).replace("/", "").trim());
        }
        allowedCommands = Set.copyOf(commands);

        confirmationEnabled = file.bool("confirmation.enabled", true);
        confirmationTimeoutMillis = Math.max(1000L, file.duration("confirmation.timeout", 30_000L));
        confirmChangePass = file.bool("confirmation.require-for.changepass", true);
        confirmForceChangePass = file.bool("confirmation.require-for.forcechangepass", true);
        confirmForceResetPass = file.bool("confirmation.require-for.forceresetpass", true);

        twoFactorEnabled = file.bool("twofa.enabled", false);
        twoFactorEnforce = file.bool("twofa.enforce-permission", true);
        twoFactorLinkTimeoutMillis = Math.max(60_000L, file.duration("twofa.link-timeout", 600_000L));
        twoFactorConfirmTimeoutMillis = Math.max(10_000L, file.duration("twofa.confirm-timeout", 120_000L));
        twoFactorBackupCount = Math.clamp(file.integer("twofa.backup-codes-count", 8), 1, 32);
        httpEnabled = file.bool("twofa.http.enabled", true);
        httpShareServerPort = file.bool("twofa.http.share-server-port", true);
        httpTunnel = file.bool("twofa.http.tunnel", false);
        httpHost = file.string("twofa.http.host", "127.0.0.1");
        httpPort = Math.clamp(file.integer("twofa.http.port", 8654), 1, 65535);
        httpPublicUrl = stripTrailingSlash(file.string("twofa.http.public-url", "http://127.0.0.1:8654"));
        telegramEnabled = file.bool("twofa.telegram.enabled", false);
        telegramToken = file.string("twofa.telegram.token", "");
        vkEnabled = file.bool("twofa.vk.enabled", false);
        vkToken = file.string("twofa.vk.token", "");
        vkGroupId = file.integer("twofa.vk.group-id", 0);
        discordEnabled = file.bool("twofa.discord.enabled", false);
        discordToken = file.string("twofa.discord.token", "");
    }

    private String stripTrailingSlash(String url) {
        return url != null && url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    private Set<String> lower(List<String> values, List<String> fallback) {
        List<String> source = values == null || values.isEmpty() ? fallback : values;
        Set<String> result = new HashSet<>(source.size());
        for (String value : source) {
            if (value != null && !value.isBlank()) {
                result.add(value.toLowerCase(Locale.ROOT).trim());
            }
        }
        return Set.copyOf(result);
    }

    private Pattern compile(String regex) {
        if (regex == null || regex.isBlank()) {
            return null;
        }
        try {
            return Pattern.compile(regex);
        } catch (PatternSyntaxException exception) {
            plugin.getLogger().warning("Некорректное регулярное выражение auth.password.pattern: "
                    + exception.getDescription());
            return null;
        }
    }

    private Punishment parsePunishment(String raw) {
        try {
            return Punishment.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException exception) {
            plugin.getLogger().warning("Неизвестный тип наказания '" + raw + "', используется KICK.");
            return Punishment.KICK;
        }
    }

    public String rawMessage(String key, String... placeholders) {
        return file.raw(key, placeholders);
    }

    public Component message(String key, String... placeholders) {
        return file.message(key, placeholders);
    }

    public String prefix() { return prefix; }
    public boolean hidePasswordsInConsole() { return hidePasswordsInConsole; }
    public boolean encryptStorage() { return encryptStorage; }
    public boolean removeLegacyFiles() { return removeLegacyFiles; }
    public int bcryptCost() { return bcryptCost; }
    public long saveIntervalMillis() { return saveIntervalMillis; }
    public long authTimeoutMillis() { return authTimeoutMillis; }
    public int maxAttempts() { return maxAttempts; }
    public int accountAttemptLimit() { return accountAttemptLimit; }
    public int ipAttemptLimit() { return ipAttemptLimit; }
    public int registrationIpLimit() { return registrationIpLimit; }
    public long attemptWindowMillis() { return attemptWindowMillis; }
    public int cryptoThreads() { return cryptoThreads; }
    public int cryptoQueueCapacity() { return cryptoQueueCapacity; }
    public long reminderIntervalMillis() { return reminderIntervalMillis; }
    public boolean showActionBar() { return showActionBar; }
    public int minPasswordLength() { return minPasswordLength; }
    public int maxPasswordLength() { return maxPasswordLength; }
    public Pattern passwordPattern() { return passwordPattern; }
    public boolean forbidNameAsPassword() { return forbidNameAsPassword; }
    public boolean rejectWeakPasswords() { return rejectWeakPasswords; }
    public boolean isWeakPassword(String password) {
        return rejectWeakPasswords && weakPasswords.contains(password.toLowerCase(Locale.ROOT));
    }
    public boolean blockMovement() { return blockMovement; }
    public boolean blockCamera() { return blockCamera; }
    public boolean blockJump() { return blockJump; }
    public boolean blockSprint() { return blockSprint; }
    public boolean blockInteraction() { return blockInteraction; }
    public boolean blockChat() { return blockChat; }
    public boolean invulnerable() { return invulnerable; }
    public boolean noPush() { return noPush; }
    public boolean blindness() { return blindness; }
    public Punishment punishment() { return punishment; }
    public long banDurationMillis() { return banDurationMillis; }
    public boolean sessionEnabled() { return sessionEnabled; }
    public long sessionDurationMillis() { return sessionDurationMillis; }
    public long sessionTimeoutMillis() { return sessionTimeoutMillis > 0L ? sessionTimeoutMillis : sessionDurationMillis; }
    public boolean sessionRequireSameIp() { return sessionRequireSameIp; }
    public Set<String> allowedCommands() { return allowedCommands; }
    public long confirmationTimeoutMillis() { return confirmationTimeoutMillis; }
    public boolean confirmChangePass() { return confirmationEnabled && confirmChangePass; }
    public boolean confirmForceChangePass() { return confirmationEnabled && confirmForceChangePass; }
    public boolean confirmForceResetPass() { return confirmationEnabled && confirmForceResetPass; }

    public boolean twoFactorEnabled() { return twoFactorEnabled; }
    public boolean twoFactorEnforce() { return twoFactorEnforce; }
    public long twoFactorLinkTimeoutMillis() { return twoFactorLinkTimeoutMillis; }
    public long twoFactorConfirmTimeoutMillis() { return twoFactorConfirmTimeoutMillis; }
    public int twoFactorBackupCount() { return twoFactorBackupCount; }
    public boolean httpEnabled() { return httpEnabled; }
    public boolean httpShareServerPort() { return httpShareServerPort; }
    public boolean httpTunnel() { return httpTunnel; }
    public String httpHost() { return httpHost; }
    public int httpPort() { return httpPort; }
    public String httpPublicUrl() { return httpPublicUrl; }
    public boolean telegramEnabled() { return telegramEnabled; }
    public String telegramToken() { return telegramToken; }
    public boolean vkEnabled() { return vkEnabled; }
    public String vkToken() { return vkToken; }
    public long vkGroupId() { return vkGroupId; }
    public boolean discordEnabled() { return discordEnabled; }
    public String discordToken() { return discordToken; }
}

