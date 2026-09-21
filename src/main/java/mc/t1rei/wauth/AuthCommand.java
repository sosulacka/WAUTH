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

import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.entity.Player;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class AuthCommand implements CommandExecutor, TabCompleter {

    private final WAuth plugin;
    private final AuthConfig config;
    private final PlayerStore store;
    private final AuthManager auth;

    public AuthCommand(WAuth plugin, AuthConfig config, PlayerStore store, AuthManager auth) {
        this.plugin = plugin;
        this.config = config;
        this.store = store;
        this.auth = auth;
    }

    @Override
    public boolean onCommand(@NotNull CommandSender sender, @NotNull Command command, @NotNull String label,
                             @NotNull String[] args) {
        return switch (command.getName().toLowerCase(Locale.ROOT)) {
            case "register" -> register(sender, args);
            case "login" -> login(sender, args);
            case "changepass" -> changePass(sender, args);
            case "forcechangepass" -> forceChangePass(sender, args);
            case "forceresetpass" -> forceResetPass(sender, args);
            case "wauth" -> service(sender, args);
            case "2fa" -> twoFactor(sender, args);
            default -> false;
        };
    }

    private boolean twoFactor(CommandSender sender, String[] args) {
        Player player = requirePlayer(sender);
        if (player == null) {
            return true;
        }
        if (!player.hasPermission("wauth.2fa.use")) {
            player.sendMessage(config.message("no-permission"));
            return true;
        }
        String sub = args.length == 0 ? "status" : args[0].toLowerCase(Locale.ROOT);
        AuthManager.Stage stage = auth.stageOf(player);
        if (stage == AuthManager.Stage.LINK_REQUIRED && !sub.equals("link") && !sub.equals("confirm")) {
            player.sendMessage(config.message("twofa-link-required-now"));
            return true;
        }
        if (stage == AuthManager.Stage.TWO_FACTOR && !sub.equals("code")) {
            player.sendMessage(config.message("twofa-awaiting-confirm"));
            return true;
        }
        if (stage != null && stage != AuthManager.Stage.LINK_REQUIRED && stage != AuthManager.Stage.TWO_FACTOR) {
            player.sendMessage(config.message("not-authenticated"));
            return true;
        }
        switch (sub) {
            case "link" -> auth.beginLink(player);
            case "confirm" -> auth.confirmLink(player);
            case "status" -> auth.twoFactorStatus(player);
            case "enable" -> auth.setTwoFactorEnabled(player, true);
            case "disable" -> auth.setTwoFactorEnabled(player, false);
            case "unlink" -> auth.unlinkTwoFactor(player);
            case "code" -> {
                if (args.length != 2) {
                    player.sendMessage(config.message("usage-twofa-code"));
                } else {
                    auth.submitBackupCode(player, args[1]);
                }
            }
            default -> player.sendMessage(config.message("usage-twofa"));
        }
        return true;
    }

    private boolean register(CommandSender sender, String[] args) {
        Player player = requirePlayer(sender);
        if (player == null) {
            return true;
        }
        if (args.length != 2) {
            player.sendMessage(config.message("usage-register"));
            return true;
        }
        auth.register(player, args[0], args[1]);
        return true;
    }

    private boolean login(CommandSender sender, String[] args) {
        Player player = requirePlayer(sender);
        if (player == null) {
            return true;
        }
        if (args.length != 1) {
            player.sendMessage(config.message("usage-login"));
            return true;
        }
        auth.login(player, args[0]);
        return true;
    }

    private boolean changePass(CommandSender sender, String[] args) {
        Player player = requirePlayer(sender);
        if (player == null) {
            return true;
        }
        if (args.length != 2) {
            player.sendMessage(config.message("usage-changepass"));
            return true;
        }
        auth.changePassword(player, args[0], args[1]);
        return true;
    }

    private boolean forceChangePass(CommandSender sender, String[] args) {
        if (args.length != 2) {
            sender.sendMessage(config.message("usage-forcechangepass"));
            return true;
        }
        auth.forceChangePassword(sender, args[0], args[1]);
        return true;
    }

    private boolean forceResetPass(CommandSender sender, String[] args) {
        if (args.length != 1) {
            sender.sendMessage(config.message("usage-forceresetpass"));
            return true;
        }
        auth.forceResetPassword(sender, args[0]);
        return true;
    }

    private boolean service(CommandSender sender, String[] args) {
        if (sender instanceof Player player && auth.isPending(player)) {
            sender.sendMessage(config.message("not-authenticated"));
            return true;
        }
        if (args.length == 2 && args[0].equalsIgnoreCase("confirm")) {
            auth.confirm(sender, args[1]);
            return true;
        }
        if (args.length == 1 && args[0].equalsIgnoreCase("reload")) {
            if (!sender.hasPermission("wauth.reload")) {
                sender.sendMessage(config.message("no-permission"));
                return true;
            }
            plugin.reloadPlugin();
            sender.sendMessage(config.message("reload-success"));
            return true;
        }
        return false;
    }

    private Player requirePlayer(CommandSender sender) {
        if (sender instanceof Player player) {
            return player;
        }
        sender.sendMessage(config.message("players-only"));
        return null;
    }

    @Override
    public @Nullable List<String> onTabComplete(@NotNull CommandSender sender, @NotNull Command command,
                                                @NotNull String label, @NotNull String[] args) {
        String name = command.getName().toLowerCase(Locale.ROOT);
        if (name.equals("2fa")) {
            if (args.length == 1) {
                String prefix = args[0].toLowerCase(Locale.ROOT);
                return List.of("link", "confirm", "status", "enable", "disable", "unlink", "code").stream()
                        .filter(o -> o.startsWith(prefix))
                        .toList();
            }
            return List.of();
        }
        if (name.equals("wauth")) {
            if (args.length == 1) {
                List<String> options = new ArrayList<>();
                if (sender.hasPermission("wauth.reload")) {
                    options.add("reload");
                }
                return options;
            }
            return List.of();
        }
        if ((name.equals("forcechangepass") || name.equals("forceresetpass")) && args.length == 1) {
            String prefix = args[0].toLowerCase(Locale.ROOT);
            return store.knownNames().stream()
                    .filter(known -> known.toLowerCase(Locale.ROOT).startsWith(prefix))
                    .limit(30L)
                    .toList();
        }
        return List.of();
    }
}

