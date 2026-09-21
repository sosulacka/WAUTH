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

import mc.t1rei.wauth.core.ConsoleFilter;
import mc.t1rei.wauth.core.Crypto;
import mc.t1rei.wauth.twofa.TwoFactorManager;
import mc.t1rei.wauth.twofa.TwoFactorStore;
import mc.t1rei.wauth.twofa.messenger.DiscordBot;
import mc.t1rei.wauth.twofa.messenger.MessengerBot;
import mc.t1rei.wauth.twofa.messenger.TelegramBot;
import mc.t1rei.wauth.twofa.messenger.VkBot;
import mc.t1rei.wauth.storage.AuthDatabase;
import mc.t1rei.wauth.web.HttpService;
import mc.t1rei.wauth.web.PortSharer;
import mc.t1rei.wauth.web.Router;
import mc.t1rei.wauth.web.TunnelService;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.PluginCommand;
import org.bukkit.command.TabCompleter;
import org.bukkit.entity.Player;
import org.bukkit.plugin.java.JavaPlugin;

import java.util.List;
import java.util.Set;

public final class WAuth extends JavaPlugin {

    private static final Set<String> SECRET_COMMANDS =
            Set.of("register", "reg", "login", "l", "changepass", "forcechangepass", "2fa", "wauth", "wa");

    private AuthConfig config;
    private PlayerStore store;
    private AuthManager authManager;
    private ConsoleFilter consoleFilter;

    private TwoFactorStore twoFactorStore;
    private AuthDatabase database;
    private TwoFactorManager twoFactorManager;
    private HttpService httpService;
    private PortSharer portSharer;
    private TunnelService tunnelService;
    private MessengerBot telegramBot;
    private MessengerBot vkBot;
    private MessengerBot discordBot;

    @Override
    public void onEnable() {
        try {
            initialize();
        } catch (RuntimeException | LinkageError exception) {
            getLogger().log(java.util.logging.Level.SEVERE,
                    "WAUTH startup failed. Player logins are blocked until storage/configuration is repaired.", exception);
            try { onDisable(); }
            catch (RuntimeException | LinkageError cleanup) {
                getLogger().log(java.util.logging.Level.SEVERE, "WAUTH startup cleanup failed", cleanup);
            }
            getServer().getPluginManager().registerEvents(new org.bukkit.event.Listener() {
                @org.bukkit.event.EventHandler(priority = org.bukkit.event.EventPriority.HIGHEST)
                public void denyLogin(org.bukkit.event.player.AsyncPlayerPreLoginEvent event) {
                    event.disallow(org.bukkit.event.player.AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                            net.kyori.adventure.text.Component.text("WAUTH unavailable. Contact the server administrator."));
                }
            }, this);
            for (Player player : getServer().getOnlinePlayers()) {
                player.kick(net.kyori.adventure.text.Component.text("WAUTH unavailable. Contact the server administrator."));
            }
        }
    }

    private void initialize() {
        config = new AuthConfig(this);

        Crypto crypto = null;
        if (config.encryptStorage() || java.nio.file.Files.exists(getDataFolder().toPath().resolve("data/store.key"))) {
            try {
                crypto = Crypto.load(getDataFolder().toPath().resolve("data").resolve("store.key"), getLogger());
            } catch (Exception exception) {
                throw new IllegalStateException("Storage encryption unavailable", exception);
            }
        }

        database = new AuthDatabase(getDataFolder().toPath(), config.encryptStorage(), crypto,
                config.removeLegacyFiles(), getLogger());
        database.open();

        store = new PlayerStore(getDataFolder().toPath(), config, getLogger(), database);
        store.useCrypto(crypto);
        store.load();

        authManager = new AuthManager(this, config, store);

        setupTwoFactor(crypto);

        authManager.start();

        if (config.hidePasswordsInConsole()) {
            consoleFilter = ConsoleFilter.install(SECRET_COMMANDS, getLogger());
        }

        getServer().getPluginManager().registerEvents(new AuthListener(config, authManager), this);

        AuthCommand command = new AuthCommand(this, config, store, authManager);
        for (String name : List.of("register", "login", "changepass", "forcechangepass", "forceresetpass", "wauth", "2fa")) {
            bind(name, command, command);
        }

        for (Player player : getServer().getOnlinePlayers()) {
            authManager.begin(player);
        }

        getLogger().info(getPluginMeta().getName() + " v" + getPluginMeta().getVersion() + " включён.");
    }

    private void setupTwoFactor(Crypto crypto) {
        if (!config.twoFactorEnabled()) {
            getLogger().info("2FA выключен (twofa.enabled: false).");
            return;
        }
        twoFactorStore = new TwoFactorStore(getDataFolder().toPath(), store, getLogger(),
                config.encryptStorage(), crypto, database);
        twoFactorStore.load();

        twoFactorManager = new TwoFactorManager(getLogger(), twoFactorStore,
                config.twoFactorLinkTimeoutMillis(), config.twoFactorConfirmTimeoutMillis(),
                config.twoFactorBackupCount());

        if (config.telegramEnabled()) {
            telegramBot = new TelegramBot(getLogger(), twoFactorManager, config.telegramToken());
        }
        if (config.vkEnabled()) {
            vkBot = new VkBot(getLogger(), twoFactorManager, config.vkToken(), config.vkGroupId());
        }
        if (config.discordEnabled()) {
            discordBot = new DiscordBot(getLogger(), twoFactorManager, config.discordToken());
        }
        twoFactorManager.attachBots(telegramBot, vkBot, discordBot);
        if (telegramBot != null) {
            telegramBot.start();
        }
        if (vkBot != null) {
            vkBot.start();
        }
        if (discordBot != null) {
            discordBot.start();
        }

        authManager.attachTwoFactor(twoFactorManager);

        if (config.httpTunnel()) {
            Router router = new Router(twoFactorManager);
            httpService = new HttpService(getLogger(), router, "127.0.0.1", config.httpPort());
            try {
                httpService.start();
                tunnelService = new TunnelService(getLogger(), config.httpPort(), getDataFolder().toPath(),
                        url -> authManager.setPublicUrlOverride(url));
                tunnelService.start();
            } catch (Exception exception) {
                getLogger().severe("Не удалось запустить HTTP/туннель 2FA: " + exception);
            }
        } else if (config.httpEnabled()) {
            Router router = new Router(twoFactorManager);
            getServer().getScheduler().runTask(this, () -> startHttp(router));
        }

        getLogger().info("2FA включён.");
    }

    private void startHttp(Router router) {
        if (config.httpShareServerPort()) {
            portSharer = new PortSharer(getLogger(), router);
            if (portSharer.install()) {
                return;
            }
            portSharer = null;
        }
        httpService = new HttpService(getLogger(), router, config.httpHost(), config.httpPort());
        try {
            httpService.start();
        } catch (Exception exception) {
            getLogger().severe("Не удалось запустить HTTP-сервис 2FA: " + exception);
            httpService = null;
        }
    }

    @Override
    public void onDisable() {
        if (tunnelService != null) {
            stopSafely("tunnel", tunnelService::stop);
        }
        if (portSharer != null) {
            stopSafely("shared port", portSharer::uninstall);
        }
        if (httpService != null) {
            stopSafely("HTTP", httpService::stop);
        }
        if (telegramBot != null) {
            stopSafely("Telegram", telegramBot::stop);
        }
        if (vkBot != null) {
            stopSafely("VK", vkBot::stop);
        }
        if (discordBot != null) {
            stopSafely("Discord", discordBot::stop);
        }
        if (twoFactorManager != null) {
            stopSafely("2FA workers", twoFactorManager::shutdown);
        }
        if (authManager != null) {
            stopSafely("authentication workers", authManager::shutdown);
        }
        if (twoFactorStore != null) {
            stopSafely("2FA storage", twoFactorStore::save);
        }
        if (consoleFilter != null) {
            stopSafely("console filter", consoleFilter::uninstall);
        }
        if (database != null) {
            stopSafely("database", database::close);
            database = null;
        }
        getLogger().info("WAUTH отключён.");
    }

    private void stopSafely(String service, Runnable close) {
        try { close.run(); }
        catch (RuntimeException | LinkageError failure) {
            getLogger().log(java.util.logging.Level.SEVERE, "Cannot stop WAUTH " + service, failure);
        }
    }

    public void reloadPlugin() {
        config.reload();
    }

    private void bind(String name, CommandExecutor executor, TabCompleter completer) {
        PluginCommand command = getCommand(name);
        if (command == null) {
            getLogger().warning("Команда не объявлена в plugin.yml: " + name);
            return;
        }
        command.setExecutor(executor);
        if (completer != null) {
            command.setTabCompleter(completer);
        }
    }

    public AuthManager authManager() {
        return authManager;
    }
}

