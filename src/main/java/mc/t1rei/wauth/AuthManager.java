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

import mc.t1rei.wauth.core.Text;
import mc.t1rei.wauth.twofa.TwoFactorManager;
import mc.t1rei.wauth.twofa.BotAccountService;
import mc.t1rei.wauth.core.AttemptLimiter;
import mc.t1rei.wauth.core.BoundedExecutor;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.event.ClickEvent;
import net.kyori.adventure.text.event.HoverEvent;
import org.bukkit.Location;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.potion.PotionEffect;
import org.bukkit.potion.PotionEffectType;
import org.bukkit.scheduler.BukkitTask;
import org.bukkit.util.Vector;

import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class AuthManager {

    public enum Stage { REGISTER, LOGIN, TWO_FACTOR, LINK_REQUIRED }

    private static final class Pending {
        private Stage stage;
        private final Location frozen;
        private final float walkSpeed;
        private final float flySpeed;
        private final boolean collidable;
        private long deadline;
        private int attempts;
        private boolean busy;
        private long lastReminder;
        private String verifiedHash;

        private Pending(Stage stage, Player player, long deadline) {
            this.stage = stage;
            this.frozen = player.getLocation().clone();
            this.walkSpeed = player.getWalkSpeed();
            this.flySpeed = player.getFlySpeed();
            this.collidable = player.isCollidable();
            this.deadline = deadline;
            this.lastReminder = System.currentTimeMillis();
        }
    }
    private record Session(String ip, long expiresAt, long timeoutAt) {}

    private record Confirmation(UUID player, long expiresAt, Runnable action) {}

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int BCRYPT_MAX_BYTES = 72;

    private final JavaPlugin plugin;
    private final AuthConfig config;
    private final PlayerStore store;
    private final Map<UUID, Pending> pending = new ConcurrentHashMap<>();
    private final Map<UUID, Session> sessions = new ConcurrentHashMap<>();
    private final java.util.Set<UUID> authenticated = ConcurrentHashMap.newKeySet();
    private final Map<String, Confirmation> confirmations = new ConcurrentHashMap<>();
    private final AttemptLimiter passwordAttempts;
    private final AttemptLimiter registrationAttempts;
    private final BoundedExecutor work;
    private final java.util.Set<UUID> accountWork = ConcurrentHashMap.newKeySet();
    private final java.util.Set<UUID> revoked = ConcurrentHashMap.newKeySet();
    private volatile boolean stopping;

    private volatile TwoFactorManager twoFactor;
    private volatile BotAccountService botAccounts;
    private volatile String publicUrlOverride;

    private BukkitTask ticker;
    private BukkitTask saver;

    public AuthManager(JavaPlugin plugin, AuthConfig config, PlayerStore store) {
        this.plugin = plugin;
        this.config = config;
        this.store = store;
        this.passwordAttempts = new AttemptLimiter(config.accountAttemptLimit(), config.ipAttemptLimit(),
                config.attemptWindowMillis(), 20_000);
        this.registrationAttempts = new AttemptLimiter(1, config.registrationIpLimit(),
                config.attemptWindowMillis(), 20_000);
        this.work = new BoundedExecutor("wauth-bcrypt", config.cryptoThreads(), config.cryptoQueueCapacity());
    }

    public void attachTwoFactor(TwoFactorManager twoFactor) {
        this.twoFactor = twoFactor;
        if (twoFactor != null) {
            botAccounts = new BotAccountService(store, twoFactor.store(), this::botPasswordError,
                    uuid -> {
                        revoked.add(uuid);
                        authenticated.remove(uuid);
                        sessions.remove(uuid);
                        twoFactor.cancel(uuid);
                        twoFactor.cancelSetup(uuid);
                        sync(() -> {
                            sessions.remove(uuid);
                            authenticated.remove(uuid);
                            Player online = plugin.getServer().getPlayer(uuid);
                            if (online != null) {
                                abandon(online);
                                pending.put(uuid, new Pending(Stage.LOGIN, online, System.currentTimeMillis()));
                                online.kick(config.message(store.isLocked(uuid) ? "account-locked" : "bot-session-revoked"));
                            }
                            revoked.remove(uuid);
                        });
                    }, config.confirmationTimeoutMillis());
            twoFactor.attachBotAccounts(botAccounts);
        }
        registerLinkConfirm();
    }

    public void setPublicUrlOverride(String url) {
        this.publicUrlOverride = url;
    }

    public void start() {
        ticker = plugin.getServer().getScheduler().runTaskTimer(plugin, this::tick, 20L, 20L);
        long saveTicks = Math.max(20L, config.saveIntervalMillis() / 50L);
        saver = plugin.getServer().getScheduler()
                .runTaskTimerAsynchronously(plugin, store::save, saveTicks, saveTicks);
    }

    public void shutdown() {
        stopping = true;
        if (ticker != null) {
            ticker.cancel();
        }
        if (saver != null) {
            saver.cancel();
        }
        work.close();
        if (botAccounts != null) botAccounts.close();
        for (Player player : plugin.getServer().getOnlinePlayers()) {
            Pending state = pending.remove(player.getUniqueId());
            if (state != null) {
                restore(player, state);
            } else {
                resetPlayerState(player);
            }
        }
        confirmations.clear();
        authenticated.clear();
        store.save();
    }

    public boolean isPending(Player player) {
        return pending.containsKey(player.getUniqueId()) || loginBlocked(player.getUniqueId());
    }

    public boolean loginBlocked(UUID uuid) { return store.isLocked(uuid) || revoked.contains(uuid); }

    public Location frozenLocation(Player player) {
        Pending state = pending.get(player.getUniqueId());
        return state == null ? null : state.frozen;
    }

    public void begin(Player player) {
        UUID uuid = player.getUniqueId();
        if (pending.containsKey(uuid)) {
            return;
        }
        authenticated.remove(uuid);
        if (loginBlocked(uuid)) {
            pending.put(uuid, new Pending(Stage.LOGIN, player, System.currentTimeMillis()));
            player.kick(config.message("account-locked"));
            return;
        }
        boolean registered = store.isRegistered(uuid);
        if (registered && consumeSession(player)) {
            if (requiresTwoFactor(player)) {
                Pending state = new Pending(Stage.LOGIN, player,
                        System.currentTimeMillis() + config.authTimeoutMillis());
                pending.put(uuid, state);
                freeze(player);
                state.verifiedHash = store.byUuid(uuid).map(PlayerStore.Account::hash).orElse(null);
                proceedAfterPassword(player, state, "session-restored");
            } else {
                authenticated.add(uuid);
                store.byUuid(uuid).ifPresent(account -> store.markLogin(account, addressOf(player)));
                if (twoFactor != null) twoFactor.notifyLogin(uuid, player.getName(), addressOf(player));
                player.sendMessage(config.message("session-restored"));
            }
            return;
        }
        Pending state = new Pending(registered ? Stage.LOGIN : Stage.REGISTER, player,
                System.currentTimeMillis() + config.authTimeoutMillis());
        pending.put(uuid, state);
        freeze(player);
        player.sendMessage(config.message(registered ? "join-login" : "join-register",
                "%player%", player.getName(),
                "%time%", Text.formatDuration(config.authTimeoutMillis())));
    }

    public void abandon(Player player) {
        authenticated.remove(player.getUniqueId());
        confirmations.values().removeIf(c -> c.player().equals(player.getUniqueId()));
        Pending state = pending.remove(player.getUniqueId());
        if (state != null) {
            restore(player, state);
        }
        if (twoFactor != null) {
            twoFactor.cancel(player.getUniqueId());
            twoFactor.cancelSetup(player.getUniqueId());
        }
    }

    private void freeze(Player player) {
        player.setWalkSpeed(0.0F);
        player.setFlySpeed(0.0F);
        if (config.noPush()) {
            player.setCollidable(false);
        }
        if (config.blindness()) {
            player.addPotionEffect(new PotionEffect(PotionEffectType.BLINDNESS, PotionEffect.INFINITE_DURATION, 0,
                    false, false, false));
        }
    }

    private void restore(Player player, Pending state) {
        player.setWalkSpeed(state.walkSpeed <= 0.0F ? 0.2F : state.walkSpeed);
        player.setFlySpeed(state.flySpeed <= 0.0F ? 0.1F : state.flySpeed);
        player.setInvulnerable(false);
        player.setNoDamageTicks(0);
        player.setCollidable(state.collidable);
        player.setFallDistance(0.0F);
        player.setVelocity(new Vector());
        if (config.blindness()) {
            player.removePotionEffect(PotionEffectType.BLINDNESS);
        }
    }

    private void tick() {
        long now = System.currentTimeMillis();
        if (twoFactor != null) {
            twoFactor.tick();
        }
        confirmations.entrySet().removeIf(entry -> entry.getValue().expiresAt() <= now);
        sessions.entrySet().removeIf(entry -> entry.getValue().expiresAt() <= now
                || entry.getValue().timeoutAt() <= now);
        pending.keySet().removeIf(uuid -> {
            Player online = plugin.getServer().getPlayer(uuid);
            return online == null || !online.isOnline();
        });
        for (Player player : plugin.getServer().getOnlinePlayers()) {
            Pending state = pending.get(player.getUniqueId());
            if (state == null) {
                if (player.getWalkSpeed() == 0.0F && player.getFlySpeed() == 0.0F) {
                    resetPlayerState(player);
                }
                continue;
            }
            if (state.stage == Stage.LINK_REQUIRED && twoFactor != null
                    && twoFactor.store().isActive(player.getUniqueId())) {
                complete(player, state, "login-success");
                continue;
            }
            long left = state.deadline - now;
            if (left <= 0L) {
                punish(player, state, timeoutCause(state.stage));
                continue;
            }
            if (config.showActionBar()) {
                player.sendActionBar(config.message(actionBarKey(state.stage),
                        "%time%", Text.formatDuration(left), "%player%", player.getName()));
            }
            if (now - state.lastReminder >= config.reminderIntervalMillis()) {
                state.lastReminder = now;
                player.sendMessage(config.message(reminderKey(state.stage),
                        "%time%", Text.formatDuration(left), "%player%", player.getName()));
            }
        }
    }

    private void punish(Player player, Pending state, String cause) {
        sessions.remove(player.getUniqueId());
        authenticated.remove(player.getUniqueId());
        if (twoFactor != null) {
            twoFactor.cancel(player.getUniqueId());
        }
        restore(player, state);
        boolean ban = config.punishment() == AuthConfig.Punishment.BAN;
        String key = (ban ? "ban-" : "kick-") + cause;
        Component reason = config.message(key,
                "%time%", Text.formatDuration(config.authTimeoutMillis()),
                "%duration%", Text.formatDuration(config.banDurationMillis()),
                "%player%", player.getName());
        if (ban) {
            player.ban(config.rawMessage("ban-reason"),
                    java.time.Duration.ofMillis(config.banDurationMillis()),
                    "WAUTH");
        }
        player.kick(reason);
    }

    private void resetPlayerState(Player player) {
        player.setWalkSpeed(0.2F);
        player.setFlySpeed(0.1F);
        player.setInvulnerable(false);
        player.setNoDamageTicks(0);
        player.setCollidable(true);
        player.setFallDistance(0.0F);
        player.setVelocity(new Vector());
        player.removePotionEffect(PotionEffectType.BLINDNESS);
    }

    public void register(Player player, String password, String confirmation) {
        Pending state = pending.get(player.getUniqueId());
        if (state == null) {
            player.sendMessage(config.message("already-authenticated"));
            return;
        }
        if (state.stage != Stage.REGISTER) {
            player.sendMessage(config.message("already-registered"));
            return;
        }
        if (state.busy) {
            player.sendMessage(config.message("busy"));
            return;
        }
        if (!password.equals(confirmation)) {
            player.sendMessage(config.message("password-mismatch"));
            return;
        }
        if (!validate(player, password)) {
            return;
        }
        long retry = registrationAttempts.acquire(player.getUniqueId(), addressOf(player));
        if (retry > 0) {
            player.sendMessage(config.message("rate-limited", "%time%", Text.formatDuration(retry)));
            return;
        }
        state.busy = true;
        char[] secret = password.toCharArray();
        UUID uuid = player.getUniqueId();
        String name = player.getName();
        submitWork(player, state, () -> {
            String hash = store.hash(secret);
            if (pending.get(uuid) != state || stopping) return;
            long now = System.currentTimeMillis();
            boolean created = store.register(new PlayerStore.Account(uuid, name, hash, now, 0, ""));
            sync(() -> {
                state.busy = false;
                if (!player.isOnline() || pending.get(player.getUniqueId()) != state) {
                    return;
                }
                if (!created) {
                    player.sendMessage(config.message("already-registered"));
                    return;
                }
                state.verifiedHash = hash;
                proceedAfterPassword(player, state, "register-success");
            });
        }, secret);
    }

    public void login(Player player, String password) {
        Pending state = pending.get(player.getUniqueId());
        if (state == null) {
            player.sendMessage(config.message("already-authenticated"));
            return;
        }
        if (state.stage != Stage.LOGIN) {
            player.sendMessage(config.message("not-registered"));
            return;
        }
        if (state.busy) {
            player.sendMessage(config.message("busy"));
            return;
        }
        Optional<PlayerStore.Account> account = store.byUuid(player.getUniqueId());
        if (account.isEmpty()) {
            player.sendMessage(config.message("not-registered"));
            return;
        }
        long retry = passwordAttempts.acquire(player.getUniqueId(), addressOf(player));
        if (retry > 0) {
            player.sendMessage(config.message("rate-limited", "%time%", Text.formatDuration(retry)));
            return;
        }
        state.busy = true;
        char[] secret = password.toCharArray();
        String hash = account.get().hash();
        submitWork(player, state, () -> {
            boolean ok = store.verify(secret, hash);
            sync(() -> {
                state.busy = false;
                if (!player.isOnline() || pending.get(player.getUniqueId()) != state
                        || !store.byUuid(player.getUniqueId()).map(a -> a.hash().equals(hash)).orElse(false)) {
                    return;
                }
                if (ok) {
                    state.verifiedHash = hash;
                    proceedAfterPassword(player, state, "login-success");
                    return;
                }
                state.attempts++;
                int max = config.maxAttempts();
                if (max > 0 && state.attempts >= max) {
                    punish(player, state, "attempts");
                    return;
                }
                player.sendMessage(config.message("wrong-password",
                        "%attempts%", max > 0 ? String.valueOf(max - state.attempts) : "∞",
                        "%max%", String.valueOf(max)));
            });
        }, secret);
    }

    private void complete(Player player, Pending state, String messageKey) {
        if (loginBlocked(player.getUniqueId()) || !store.byUuid(player.getUniqueId())
                .map(a -> a.hash().equals(state.verifiedHash)).orElse(false)) {
            player.kick(config.message("bot-session-revoked"));
            return;
        }
        if (!pending.remove(player.getUniqueId(), state)) {
            return;
        }
        restore(player, state);
        authenticated.add(player.getUniqueId());
        store.byUuid(player.getUniqueId()).ifPresent(account -> store.markLogin(account, addressOf(player)));
        if (twoFactor != null) twoFactor.notifyLogin(player.getUniqueId(), player.getName(), addressOf(player));
        openSession(player);
        flush();
        player.sendMessage(config.message(messageKey, "%player%", player.getName()));
    }

    private boolean requiresTwoFactor(Player player) {
        if (twoFactor == null || !config.twoFactorEnabled()) {
            return false;
        }
        if (twoFactor.store().isActive(player.getUniqueId())) {
            return true;
        }
        return config.twoFactorEnforce() && player.hasPermission("wauth.2fa.required");
    }

    private void proceedAfterPassword(Player player, Pending state, String successKey) {
        UUID uuid = player.getUniqueId();
        if (loginBlocked(uuid) || !store.byUuid(uuid).map(a -> a.hash().equals(state.verifiedHash)).orElse(false)) {
            player.kick(config.message("bot-session-revoked"));
            return;
        }
        if (twoFactor == null || !config.twoFactorEnabled()) {
            complete(player, state, successKey);
            return;
        }
        boolean active = twoFactor.store().isActive(uuid);
        if (active) {
            beginTwoFactor(player, state, successKey);
            return;
        }
        boolean mustLink = config.twoFactorEnforce() && player.hasPermission("wauth.2fa.required");
        if (mustLink) {
            state.stage = Stage.LINK_REQUIRED;
            state.deadline = System.currentTimeMillis() + config.twoFactorLinkTimeoutMillis();
            state.lastReminder = System.currentTimeMillis();
            player.sendMessage(config.message("twofa-link-required",
                    "%time%", Text.formatDuration(config.twoFactorLinkTimeoutMillis())));
            return;
        }
        complete(player, state, successKey);
    }

    private void beginTwoFactor(Player player, Pending state, String successKey) {
        UUID uuid = player.getUniqueId();
        state.stage = Stage.TWO_FACTOR;
        state.deadline = System.currentTimeMillis() + config.twoFactorConfirmTimeoutMillis() + 5_000L;
        state.lastReminder = System.currentTimeMillis();
        Runnable onApprove = () -> sync(() -> {
            Pending current = pending.get(uuid);
            if (current == state && current.stage == Stage.TWO_FACTOR && player.isOnline()) {
                complete(player, current, successKey);
            }
        });
        Runnable onDeny = () -> sync(() -> {
            if (pending.get(uuid) == state) denyTwoFactor(player, "twofa");
        });
        Optional<String> token = twoFactor.requestLogin(uuid, player.getName(), addressOf(player), onApprove, onDeny);
        if (token.isEmpty()) {
            denyTwoFactor(player, "twofa");
            return;
        }
        player.sendMessage(config.message("twofa-confirm-sent",
                "%time%", Text.formatDuration(config.twoFactorConfirmTimeoutMillis())));
    }

    private void denyTwoFactor(Player player, String cause) {
        Pending state = pending.get(player.getUniqueId());
        if (state != null && state.stage == Stage.TWO_FACTOR) {
            punish(player, state, cause);
        }
    }

    public void submitBackupCode(Player player, String code) {
        Pending state = pending.get(player.getUniqueId());
        if (twoFactor == null || state == null || state.stage != Stage.TWO_FACTOR) {
            player.sendMessage(config.message("twofa-no-pending"));
            return;
        }
        if (state.busy) {
            player.sendMessage(config.message("busy"));
            return;
        }
        if (!allowAttempt(player)) return;
        state.busy = true;
        UUID uuid = player.getUniqueId();
        submitWork(player, state, () -> {
            boolean ok = twoFactor.store().consumeBackup(uuid, code);
            sync(() -> {
                state.busy = false;
                Pending current = pending.get(uuid);
                if (current != state || current.stage != Stage.TWO_FACTOR || !player.isOnline()) {
                    return;
                }
                if (ok) {
                    twoFactor.cancel(uuid);
                    int left = twoFactor.store().backupLeft(uuid);
                    complete(player, current, "login-success");
                    player.sendMessage(config.message("twofa-backup-used", "%left%", String.valueOf(left)));
                } else {
                    state.attempts++;
                    if (state.attempts >= Math.max(1, config.maxAttempts())) {
                        punish(player, state, "attempts");
                        return;
                    }
                    player.sendMessage(config.message("twofa-backup-invalid"));
                }
            });
        });
    }

    private String timeoutCause(Stage stage) {
        return switch (stage) {
            case TWO_FACTOR -> "twofa";
            case LINK_REQUIRED -> "twofa-link";
            default -> "timeout";
        };
    }

    private String actionBarKey(Stage stage) {
        return switch (stage) {
            case REGISTER -> "actionbar-register";
            case TWO_FACTOR -> "actionbar-twofa";
            case LINK_REQUIRED -> "actionbar-twofa-link";
            default -> "actionbar-login";
        };
    }

    private String reminderKey(Stage stage) {
        return switch (stage) {
            case REGISTER -> "reminder-register";
            case TWO_FACTOR -> "reminder-twofa";
            case LINK_REQUIRED -> "reminder-twofa-link";
            default -> "reminder-login";
        };
    }

    public void beginLink(Player player) {
        if (twoFactor == null || !config.twoFactorEnabled()) {
            player.sendMessage(config.message("twofa-disabled"));
            return;
        }
        if (isPending(player)) {
            Pending state = pending.get(player.getUniqueId());
            if (state != null && state.stage != Stage.LINK_REQUIRED) {
                player.sendMessage(config.message("not-authenticated"));
                return;
            }
        }
        if (twoFactor.store().isLinked(player.getUniqueId())) {
            twoFactorStatus(player);
            return;
        }
        TwoFactorManager.SetupOpen open = twoFactor.createSetup(player.getUniqueId(), player.getName());
        String base = publicUrlOverride != null ? publicUrlOverride : config.httpPublicUrl();
        String url = base + "/setup#token=" + open.sessionToken();
        player.sendMessage(config.message("twofa-link-url", "%url%", url)
                .clickEvent(ClickEvent.openUrl(url))
                .hoverEvent(HoverEvent.showText(config.message("twofa-link-url-hover"))));
    }

    private void registerLinkConfirm() {
        if (twoFactor == null) {
            return;
        }
        twoFactor.onLinkConfirmNeeded(request -> sync(() -> {
            Player player = plugin.getServer().getPlayer(request.uuid());
            if (player == null || !player.isOnline()) {
                return;
            }
            sendConfirmPrompt(player, request);
        }));
    }

    private void sendConfirmPrompt(Player player, TwoFactorManager.LinkConfirmRequest request) {
        player.sendMessage(config.message("twofa-confirm-link-prompt",
                "%provider%", request.provider().name(),
                "%messenger%", maskMessenger(request.messengerId())));
        player.sendMessage(config.message("twofa-confirm-link-button")
                .clickEvent(ClickEvent.runCommand("/2fa confirm"))
                .hoverEvent(HoverEvent.showText(config.message("twofa-confirm-link-hover"))));
    }

    private String maskMessenger(String id) {
        if (id == null || id.length() <= 4) {
            return "•••";
        }
        return id.substring(0, 2) + "•••" + id.substring(id.length() - 3);
    }

    public void confirmLink(Player player) {
        if (twoFactor == null || !config.twoFactorEnabled()) {
            player.sendMessage(config.message("twofa-disabled"));
            return;
        }
        twoFactor.confirmLinkClick(player.getUniqueId()).whenComplete((result, failure) -> sync(() -> {
            if (!player.isOnline()) return;
            if (failure != null) {
                plugin.getLogger().log(java.util.logging.Level.SEVERE, "2FA linking failed", failure);
                player.sendMessage(config.message("operation-failed"));
            } else if (!result.known()) {
                player.sendMessage(config.message("twofa-confirm-link-none"));
            } else if (!result.done()) {
                player.sendMessage(config.message("twofa-confirm-link-progress", "%left%", String.valueOf(result.remaining())));
            } else {
                player.sendMessage(config.message("twofa-linked", "%provider%", result.provider().name()));
            }
        }));
    }

    public void twoFactorStatus(Player player) {
        if (twoFactor == null || !config.twoFactorEnabled()) {
            player.sendMessage(config.message("twofa-disabled"));
            return;
        }
        UUID uuid = player.getUniqueId();
        var binding = twoFactor.store().binding(uuid);
        if (binding.isEmpty() || !binding.get().linked()) {
            player.sendMessage(config.message("twofa-status-unlinked"));
            return;
        }
        player.sendMessage(config.message("twofa-status-linked",
                "%provider%", binding.get().provider().name(),
                "%state%", binding.get().enabled() ? "вкл" : "выкл",
                "%left%", String.valueOf(twoFactor.store().backupLeft(uuid))));
    }

    public void setTwoFactorEnabled(Player player, boolean enabled) {
        if (twoFactor == null || !config.twoFactorEnabled()) {
            player.sendMessage(config.message("twofa-disabled"));
            return;
        }
        UUID uuid = player.getUniqueId();
        if (!twoFactor.store().isLinked(uuid)) {
            player.sendMessage(config.message("twofa-status-unlinked"));
            return;
        }
        if (!enabled && config.twoFactorEnforce() && player.hasPermission("wauth.2fa.required")) {
            player.sendMessage(config.message("twofa-required-cannot-disable"));
            return;
        }
        if (!accountWork.add(uuid)) {
            player.sendMessage(config.message("busy"));
            return;
        }
        submitWork(player, null, () -> {
            twoFactor.store().setEnabled(uuid, enabled);
            sync(() -> {
                accountWork.remove(uuid);
                if (player.isOnline()) player.sendMessage(config.message(enabled ? "twofa-enabled" : "twofa-disabled-ok"));
            });
        });
    }

    public void unlinkTwoFactor(Player player) {
        if (twoFactor == null || !config.twoFactorEnabled()) {
            player.sendMessage(config.message("twofa-disabled"));
            return;
        }
        UUID uuid = player.getUniqueId();
        if (!twoFactor.store().isLinked(uuid)) {
            player.sendMessage(config.message("twofa-status-unlinked"));
            return;
        }
        if (config.twoFactorEnforce() && player.hasPermission("wauth.2fa.required")) {
            player.sendMessage(config.message("twofa-required-cannot-disable"));
            return;
        }
        if (!accountWork.add(uuid)) {
            player.sendMessage(config.message("busy"));
            return;
        }
        twoFactor.cancel(uuid);
        twoFactor.cancelSetup(uuid);
        submitWork(player, null, () -> {
            twoFactor.store().unbind(uuid);
            sync(() -> {
                accountWork.remove(uuid);
                if (player.isOnline()) player.sendMessage(config.message("twofa-unlinked"));
            });
        });
    }

    public Stage stageOf(Player player) {
        Pending state = pending.get(player.getUniqueId());
        return state == null ? null : state.stage;
    }

    private boolean validate(Player player, String password) {
        if (password.length() < config.minPasswordLength()) {
            player.sendMessage(config.message("password-too-short", "%min%", String.valueOf(config.minPasswordLength())));
            return false;
        }
        if (password.length() > config.maxPasswordLength()) {
            player.sendMessage(config.message("password-too-long", "%max%", String.valueOf(config.maxPasswordLength())));
            return false;
        }
        if (!withinHashLimit(player, password)) {
            return false;
        }
        if (config.forbidNameAsPassword() && password.equalsIgnoreCase(player.getName())) {
            player.sendMessage(config.message("password-is-name"));
            return false;
        }
        if (config.isWeakPassword(password)) {
            player.sendMessage(config.message("password-too-weak"));
            return false;
        }
        if (config.passwordPattern() != null && !config.passwordPattern().matcher(password).matches()) {
            player.sendMessage(config.message("password-pattern"));
            return false;
        }
        return true;
    }

    private String botPasswordError(String playerName, String password) {
        if (password == null || password.length() < config.minPasswordLength()) return "Пароль слишком короткий.";
        if (password.length() > config.maxPasswordLength()
                || password.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > BCRYPT_MAX_BYTES) return "Пароль слишком длинный.";
        if (config.forbidNameAsPassword() && password.equalsIgnoreCase(playerName)) return "Пароль не может совпадать с ником.";
        if (config.isWeakPassword(password)) return "Этот пароль слишком простой.";
        if (config.passwordPattern() != null && !config.passwordPattern().matcher(password).matches()) return "Пароль не соответствует требованиям.";
        return null;
    }

    public void changePassword(Player player, String currentPassword, String newPassword) {
        if (isPending(player)) {
            player.sendMessage(config.message("not-authenticated"));
            return;
        }
        Optional<PlayerStore.Account> account = store.byUuid(player.getUniqueId());
        if (account.isEmpty()) {
            player.sendMessage(config.message("not-registered"));
            return;
        }
        if (currentPassword.equals(newPassword)) {
            player.sendMessage(config.message("password-same-as-old"));
            return;
        }
        if (!validate(player, newPassword)) {
            return;
        }
        Runnable action = () -> applyChange(player, account.get(), currentPassword, newPassword);
        if (config.confirmChangePass()) {
            requestConfirmation(player, config.rawMessage("confirm-action-changepass"), action);
        } else {
            action.run();
        }
    }

    private void applyChange(Player player, PlayerStore.Account account, String currentPassword, String newPassword) {
        if (!player.isOnline() || isPending(player) || !allowAttempt(player)) return;
        if (!accountWork.add(player.getUniqueId())) {
            player.sendMessage(config.message("busy"));
            return;
        }
        char[] current = currentPassword.toCharArray();
        char[] fresh = newPassword.toCharArray();
        sessions.remove(account.uuid());
        submitWork(player, null, () -> {
            boolean ok = store.verify(current, account.hash());
            String hash = ok ? store.hash(fresh) : null;
            boolean updated = ok && !stopping && store.updateHash(account, hash);
            sync(() -> {
                accountWork.remove(player.getUniqueId());
                if (!player.isOnline() || isPending(player)) {
                    return;
                }
                if (!ok) {
                    player.sendMessage(config.message("wrong-current-password"));
                    return;
                }
                if (!updated) {
                    player.sendMessage(config.message("wrong-current-password"));
                    return;
                }
                sessions.remove(account.uuid());
                flush();
                player.sendMessage(config.message("changepass-success"));
            });
        }, current, fresh);
    }

    public void forceChangePassword(CommandSender sender, String targetName, String newPassword) {
        if (!authorizedAdmin(sender, "wauth.forcechangepass")) return;
        Optional<PlayerStore.Account> account = findAdminTarget(sender, targetName);
        if (account.isEmpty()) {
            return;
        }
        PlayerStore.Account target = account.get();
        if (newPassword.length() < config.minPasswordLength()) {
            sender.sendMessage(config.message("password-too-short", "%min%", String.valueOf(config.minPasswordLength())));
            return;
        }
        if (newPassword.length() > config.maxPasswordLength()) {
            sender.sendMessage(config.message("password-too-long", "%max%", String.valueOf(config.maxPasswordLength())));
            return;
        }
        if (!withinHashLimit(sender, newPassword)) {
            return;
        }
        if (config.isWeakPassword(newPassword)) {
            sender.sendMessage(config.message("password-too-weak"));
            return;
        }
        Runnable action = () -> {
            if (!authorizedAdmin(sender, "wauth.forcechangepass")) return;
            char[] fresh = newPassword.toCharArray();
            sessions.remove(target.uuid());
            submitWork(sender, null, () -> {
                String hash = store.hash(fresh);
                boolean updated = !stopping && store.updateHash(target, hash);
                sync(() -> {
                    if (!updated) {
                        sender.sendMessage(config.message("operation-failed"));
                        return;
                    }
                    sessions.remove(target.uuid());
                    sender.sendMessage(config.message("force-changepass-success", "%player%", target.name()));
                    Player online = plugin.getServer().getPlayer(target.uuid());
                    if (online != null) {
                        online.sendMessage(config.message("force-changepass-notify"));
                        abandon(online);
                        begin(online);
                    }
                });
            }, fresh);
        };
        dispatch(sender, config.confirmForceChangePass(),
                config.rawMessage("confirm-action-forcechangepass", "%player%", target.name()), action);
    }

    public void forceResetPassword(CommandSender sender, String targetName) {
        if (!authorizedAdmin(sender, "wauth.forceresetpass")) return;
        Optional<PlayerStore.Account> account = findAdminTarget(sender, targetName);
        if (account.isEmpty()) {
            return;
        }
        PlayerStore.Account target = account.get();
        Runnable action = () -> {
            if (!authorizedAdmin(sender, "wauth.forceresetpass")) return;
            sessions.remove(target.uuid());
            submitWork(sender, null, () -> {
                if (stopping) return;
                store.remove(target.uuid());
                sync(() -> {
                    sessions.remove(target.uuid());
                    sender.sendMessage(config.message("force-resetpass-success", "%player%", target.name()));
                    Player online = plugin.getServer().getPlayer(target.uuid());
                    if (online != null) {
                        online.sendMessage(config.message("force-resetpass-notify"));
                        abandon(online);
                        begin(online);
                    }
                });
            });
        };
        dispatch(sender, config.confirmForceResetPass(),
                config.rawMessage("confirm-action-forceresetpass", "%player%", target.name()), action);
    }

    private Optional<PlayerStore.Account> findAdminTarget(CommandSender sender, String target) {
        var account = store.byTarget(target);
        if (account.isPresent()) return account;
        var ids = store.matchingIds(target);
        if (ids.size() > 1) {
            sender.sendMessage(config.message("player-ambiguous", "%player%", target,
                    "%uuids%", ids.stream().map(UUID::toString).collect(java.util.stream.Collectors.joining(", "))));
        } else {
            sender.sendMessage(config.message("player-not-found", "%player%", target));
        }
        return Optional.empty();
    }

    private void dispatch(CommandSender sender, boolean needsConfirmation, String description, Runnable action) {
        if (needsConfirmation && sender instanceof Player player) {
            requestConfirmation(player, description, action);
        } else {
            action.run();
        }
    }

    private void requestConfirmation(Player player, String description, Runnable action) {
        confirmations.values().removeIf(c -> c.player().equals(player.getUniqueId()));
        byte[] raw = new byte[8];
        RANDOM.nextBytes(raw);
        String token = HexFormat.of().formatHex(raw);
        confirmations.put(token, new Confirmation(player.getUniqueId(),
                System.currentTimeMillis() + config.confirmationTimeoutMillis(), action));
        player.sendMessage(config.message("confirm-prompt", "%action%", description));
        player.sendMessage(config.message("confirm-button",
                        "%time%", Text.formatDuration(config.confirmationTimeoutMillis()))
                .clickEvent(ClickEvent.runCommand("/wauth confirm " + token))
                .hoverEvent(HoverEvent.showText(config.message("confirm-hover"))));
    }

    public void confirm(CommandSender sender, String token) {
        if (sender instanceof Player p && isPending(p)) {
            sender.sendMessage(config.message("not-authenticated"));
            return;
        }
        String normalized = token == null ? "" : token.trim().toLowerCase(Locale.ROOT);
        Confirmation confirmation = confirmations.get(normalized);
        if (confirmation == null) {
            sender.sendMessage(config.message("confirm-unknown"));
            return;
        }
        if (!(sender instanceof Player player) || !confirmation.player().equals(player.getUniqueId())) {
            sender.sendMessage(config.message("confirm-unknown"));
            return;
        }
        confirmations.remove(normalized, confirmation);
        if (confirmation.expiresAt() <= System.currentTimeMillis()) {
            sender.sendMessage(config.message("confirm-expired"));
            return;
        }
        confirmation.action().run();
    }

    private void openSession(Player player) {
        if (config.sessionEnabled() && config.sessionDurationMillis() > 0L) {
            long now = System.currentTimeMillis();
            sessions.put(player.getUniqueId(),
                    new Session(addressOf(player), now + config.sessionDurationMillis(),
                            now + config.sessionTimeoutMillis()));
        }
    }

    private boolean authorizedAdmin(CommandSender sender, String permission) {
        if (!sender.hasPermission(permission)) {
            sender.sendMessage(config.message("no-permission"));
            return false;
        }
        if (sender instanceof Player player && (!player.isOnline() || isPending(player))) {
            sender.sendMessage(config.message("not-authenticated"));
            return false;
        }
        return true;
    }

    public void refreshSession(Player player) {
        if (authenticated.contains(player.getUniqueId()) && !isPending(player)) {
            openSession(player);
        }
    }

    private boolean consumeSession(Player player) {
        if (!config.sessionEnabled() || loginBlocked(player.getUniqueId())) {
            return false;
        }
        long now = System.currentTimeMillis();
        Session session = sessions.get(player.getUniqueId());
        if (session == null || session.expiresAt() <= now || session.timeoutAt() <= now) {
            sessions.remove(player.getUniqueId());
            return false;
        }
        if (config.sessionRequireSameIp() && !session.ip().equals(addressOf(player))) {
            sessions.remove(player.getUniqueId());
            return false;
        }
        return true;
    }

    private String addressOf(Player player) {
        java.net.InetSocketAddress address = player.getAddress();
        return address == null || address.getAddress() == null ? "unknown" : address.getAddress().getHostAddress();
    }

    private boolean withinHashLimit(CommandSender sender, String password) {
        if (password.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > BCRYPT_MAX_BYTES) {
            sender.sendMessage(config.message("password-too-long-bytes", "%max%", String.valueOf(BCRYPT_MAX_BYTES)));
            return false;
        }
        return true;
    }

    private boolean allowAttempt(Player player) {
        long retry = passwordAttempts.acquire(player.getUniqueId(), addressOf(player));
        if (retry == 0) return true;
        player.sendMessage(config.message("rate-limited", "%time%", Text.formatDuration(retry)));
        return false;
    }

    private void submitWork(CommandSender sender, Pending state, Runnable action, char[]... secrets) {
        Runnable wipe = () -> { for (char[] secret : secrets) Text.wipe(secret); };
        Runnable task = () -> {
            try {
                if (!stopping) action.run();
            } catch (RuntimeException failure) {
                plugin.getLogger().log(java.util.logging.Level.SEVERE, "WAUTH background operation failed", failure);
                sync(() -> {
                    if (state != null) state.busy = false;
                    if (sender instanceof Player player) accountWork.remove(player.getUniqueId());
                    sender.sendMessage(config.message("operation-failed"));
                });
            } finally {
                wipe.run();
            }
        };
        if (!work.submit(task, wipe)) {
            wipe.run();
            if (state != null) state.busy = false;
            if (sender instanceof Player player) accountWork.remove(player.getUniqueId());
            sender.sendMessage(config.message("busy"));
        }
    }

    private void flush() {
        if (plugin.isEnabled() && !stopping) {
            work.submit(store::save);
        } else {
            store.save();
        }
    }

    private void sync(Runnable runnable) {
        if (plugin.isEnabled() && !stopping) {
            try {
                plugin.getServer().getScheduler().runTask(plugin, () -> {
                    if (!stopping) runnable.run();
                });
            } catch (org.bukkit.plugin.IllegalPluginAccessException failure) {
                if (plugin.isEnabled() && !stopping) throw failure;
            }
        }
    }
}
