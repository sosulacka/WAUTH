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

package mc.t1rei.wauth.twofa;

import mc.t1rei.wauth.twofa.messenger.MessengerBot;
import mc.t1rei.wauth.twofa.messenger.BotReply;
import mc.t1rei.wauth.core.BoundedExecutor;

import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CompletableFuture;
import java.util.logging.Logger;

public final class TwoFactorManager {

    private record LinkRequest(UUID uuid, String playerName, long expiresAt) {}

    private record SetupSession(UUID uuid, String playerName, String linkCode, long expiresAt) {}

    public record SetupInfo(String playerName, String code, long expiresAt) {}

    public record SetupStatus(boolean linked, boolean needsConfirm, Provider provider, List<String> backup) {}

    private record LoginRequest(UUID uuid, String playerName, Provider provider, String messengerId,
                                TwoFactorStore.Binding binding, String ip, long expiresAt, Runnable onApprove, Runnable onDeny) {}


    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int LINK_CODE_BYTES = 4;
    private static final int TOKEN_BYTES = 16;
    private static final int SETUP_TOKEN_BYTES = 64;

    private final Logger logger;
    private final TwoFactorStore store;
    private final long linkTtlMillis;
    private final long confirmTtlMillis;
    private final int backupCount;
    private final BoundedExecutor notifications = new BoundedExecutor("wauth-messenger-send", 2, 64);
    private final BoundedExecutor links = new BoundedExecutor("wauth-backup-create", 1, 16);
    private final Map<UUID, PendingConfirm> finishing = new ConcurrentHashMap<>();
    private volatile boolean stopping;

    private final Map<String, LinkRequest> linkRequests = new ConcurrentHashMap<>();
    private final Map<String, LoginRequest> loginRequests = new ConcurrentHashMap<>();
    private final Map<String, SetupSession> setupSessions = new ConcurrentHashMap<>();
    private final Map<UUID, List<String>> freshBackup = new ConcurrentHashMap<>();

    private volatile MessengerBot telegram;
    private volatile MessengerBot vk;
    private volatile MessengerBot discord;
    private volatile BotAccountService botAccounts;
    private final Map<String, Runnable> prompts = new ConcurrentHashMap<>();
    private final mc.t1rei.wauth.core.AttemptLimiter botAttempts =
            new mc.t1rei.wauth.core.AttemptLimiter(30, 30, 60_000, 20_000);

    public TwoFactorManager(Logger logger, TwoFactorStore store,
                            long linkTtlMillis, long confirmTtlMillis, int backupCount) {
        this.logger = logger;
        this.store = store;
        this.linkTtlMillis = linkTtlMillis;
        this.confirmTtlMillis = confirmTtlMillis;
        this.backupCount = backupCount;
    }

    public void attachBots(MessengerBot telegram, MessengerBot vk, MessengerBot discord) {
        this.telegram = telegram;
        this.vk = vk;
        this.discord = discord;
    }

    public void attachBotAccounts(BotAccountService service) {
        this.botAccounts = service;
    }

    public CompletableFuture<BotReply> handleBotCommand(Provider provider, String id, String input) {
        if (stopping || provider == null || id == null || !id.matches("[1-9][0-9]{0,24}") || input == null || input.length() > 512)
            return CompletableFuture.completedFuture(BotReply.text("Некорректный запрос."));
        String identity = provider + ":" + id;
        if (botAttempts.acquire(UUID.nameUUIDFromBytes(identity.getBytes(java.nio.charset.StandardCharsets.UTF_8)), identity) > 0)
            return CompletableFuture.completedFuture(BotReply.text("Слишком много запросов. Подождите минуту."));
        String command = input.trim();
        if (command.matches("(?i)[0-9a-f]{8}")) {
            LinkSubmit result = submitLinkCode(provider, id, command);
            return CompletableFuture.completedFuture(BotReply.text(result.status() == LinkStatus.NEEDS_CONFIRM
                    ? "Код принят для " + result.playerName() + ". Подтвердите привязку в игре (3 нажатия). Резервные коды появятся на сайте."
                    : "Код не найден или истёк. Создайте новый: /2fa link в игре."));
        }
        if (command.startsWith("approve:") || command.startsWith("deny:")) {
            String token = command.substring(command.indexOf(':') + 1);
            LoginRequest request = loginRequests.get(token);
            boolean approved = command.startsWith("approve:");
            boolean handled = resolve(token, approved, provider, id);
            if (handled) clearPrompt(token);
            return CompletableFuture.completedFuture(BotReply.text(handled
                    ? (approved ? "Подтверждение принято. Ожидайте уведомление об успешном входе." : "Вход отклонён.")
                        + "\nIP: " + request.ip() : "Запрос истёк или уже обработан."));
        }
        BotAccountService service = botAccounts;
        if (service == null) return CompletableFuture.completedFuture(BotReply.text("Управление аккаунтом временно недоступно."));
        return service.handle(provider, id, command).thenApply(reply -> {
            cleanupPrompts();
            return reply;
        });
    }

    public void trackPrompt(String token, Runnable delete) {
        prompts.put(token, delete);
        if (!pendingPrompt(token)) clearPrompt(token);
    }

    private boolean pendingPrompt(String token) {
        LoginRequest request = loginRequests.get(token);
        return request != null && request.expiresAt() > System.currentTimeMillis()
                || botAccounts != null && botAccounts.pending(token);
    }

    private void clearPrompt(String token) {
        Runnable delete = prompts.get(token);
        if (delete != null && notifications.submit(() -> {
            try { delete.run(); } catch (RuntimeException failure) { logger.warning("Bot prompt cleanup failed"); }
        })) prompts.remove(token, delete);
    }

    private void cleanupPrompts() {
        prompts.keySet().forEach(token -> { if (!pendingPrompt(token)) clearPrompt(token); });
    }

    public void notifyLogin(UUID uuid, String name, String ip) {
        store.binding(uuid).ifPresent(binding -> {
            MessengerBot bot = switch (binding.provider()) { case TELEGRAM -> telegram; case VK -> vk; case DISCORD -> discord; };
            if (bot != null && !notifications.submit(() -> {
                try {
                    if (store.binding(uuid).orElse(null) != binding) return;
                    bot.sendMessage(binding.messengerId(), BotReply.menu("Вход выполнен: " + name + "\nIP: " + ip
                            + "\nВремя: " + java.time.Instant.now() + "\nЕсли это не вы: /lock, затем /password."));
                } catch (RuntimeException failure) { logger.warning("Login notification delivery failed"); }
            })) logger.warning("Login notification queue full");
        });
    }

    public TwoFactorStore store() {
        return store;
    }

    public synchronized String createLinkCode(UUID uuid, String playerName) {
        if (stopping) throw new IllegalStateException("2FA is stopping");
        finishing.remove(uuid);
        pendingConfirms.remove(uuid);
        linkRequests.values().removeIf(r -> r.uuid().equals(uuid));
        byte[] raw = new byte[LINK_CODE_BYTES];
        RANDOM.nextBytes(raw);
        String code = HexFormat.of().formatHex(raw).toUpperCase(Locale.ROOT);
        linkRequests.put(code, new LinkRequest(uuid, playerName, System.currentTimeMillis() + linkTtlMillis));
        return code;
    }

    public enum LinkStatus { INVALID, NEEDS_CONFIRM }

    public record LinkSubmit(LinkStatus status, String playerName) {
        static LinkSubmit invalid() { return new LinkSubmit(LinkStatus.INVALID, null); }
        static LinkSubmit needsConfirm(String name) { return new LinkSubmit(LinkStatus.NEEDS_CONFIRM, name); }
    }

    public record LinkConfirmRequest(UUID uuid, String playerName, Provider provider, String messengerId) {}

    public record ConfirmResult(boolean known, boolean done, int remaining, Provider provider, List<String> backup) {
        static ConfirmResult none() { return new ConfirmResult(false, false, 0, null, null); }
        static ConfirmResult progress(int remaining) { return new ConfirmResult(true, false, remaining, null, null); }
        static ConfirmResult done(Provider provider, List<String> backup) { return new ConfirmResult(true, true, 0, provider, backup); }
    }

    private record PendingConfirm(UUID uuid, String playerName, Provider provider, String messengerId,
                                  String setupToken, long expiresAt, java.util.concurrent.atomic.AtomicInteger clicks) {}

    private static final int CONFIRM_CLICKS = 3;
    private final Map<UUID, PendingConfirm> pendingConfirms = new ConcurrentHashMap<>();
    private volatile java.util.function.Consumer<LinkConfirmRequest> onLinkConfirmNeeded;

    public void onLinkConfirmNeeded(java.util.function.Consumer<LinkConfirmRequest> callback) {
        this.onLinkConfirmNeeded = callback;
    }

    public synchronized LinkSubmit submitLinkCode(Provider provider, String messengerId, String rawCode) {
        if (stopping) return LinkSubmit.invalid();
        if (provider == null || messengerId == null || !messengerId.matches("[1-9][0-9]{0,24}")
                || rawCode == null || rawCode.length() > 32) {
            return LinkSubmit.invalid();
        }
        String code = rawCode == null ? "" : rawCode.trim().toUpperCase(Locale.ROOT);
        LinkRequest request = linkRequests.get(code);
        if (request == null || request.expiresAt() <= System.currentTimeMillis()) {
            return LinkSubmit.invalid();
        }
        if (finishing.containsKey(request.uuid())) return LinkSubmit.invalid();
        if (store.isLinked(request.uuid()) || store.byMessenger(provider, messengerId)
                .filter(binding -> !binding.uuid().equals(request.uuid())).isPresent()) {
            return LinkSubmit.invalid();
        }
        PendingConfirm existing = pendingConfirms.get(request.uuid());
        if (existing != null && existing.expiresAt() > System.currentTimeMillis()) {
            return existing.provider() == provider && existing.messengerId().equals(messengerId)
                    ? LinkSubmit.needsConfirm(request.playerName()) : LinkSubmit.invalid();
        }
        pendingConfirms.put(request.uuid(), new PendingConfirm(request.uuid(), request.playerName(),
                provider, messengerId, findSetupToken(request.uuid()).orElse(null), System.currentTimeMillis() + confirmTtlMillis,
                new java.util.concurrent.atomic.AtomicInteger(0)));
        java.util.function.Consumer<LinkConfirmRequest> cb = onLinkConfirmNeeded;
        if (cb != null) {
            cb.accept(new LinkConfirmRequest(request.uuid(), request.playerName(), provider, messengerId));
        }
        logger.info("2FA: код принят от " + provider + " (" + messengerId + ") для "
                + request.playerName() + " — ждём подтверждения в игре.");
        return LinkSubmit.needsConfirm(request.playerName());
    }

    public boolean hasPendingConfirm(UUID uuid) {
        PendingConfirm pc = pendingConfirms.get(uuid);
        return pc != null && pc.expiresAt() > System.currentTimeMillis();
    }

    public Optional<LinkConfirmRequest> pendingConfirm(UUID uuid) {
        PendingConfirm pc = pendingConfirms.get(uuid);
        return pc == null || pc.expiresAt() <= System.currentTimeMillis()
                ? Optional.empty()
                : Optional.of(new LinkConfirmRequest(pc.uuid(), pc.playerName(), pc.provider(), pc.messengerId()));
    }

    public synchronized CompletableFuture<ConfirmResult> confirmLinkClick(UUID uuid) {
        if (stopping || finishing.containsKey(uuid)) return CompletableFuture.completedFuture(ConfirmResult.none());
        PendingConfirm pc = pendingConfirms.get(uuid);
        if (pc == null || pc.expiresAt() <= System.currentTimeMillis()) {
            pendingConfirms.remove(uuid);
            return CompletableFuture.completedFuture(ConfirmResult.none());
        }
        if (store.isLinked(uuid) || store.byMessenger(pc.provider(), pc.messengerId())
                .filter(binding -> !binding.uuid().equals(uuid)).isPresent()) {
            pendingConfirms.remove(uuid);
            return CompletableFuture.completedFuture(ConfirmResult.none());
        }
        int done = pc.clicks().incrementAndGet();
        if (done < CONFIRM_CLICKS) {
            return CompletableFuture.completedFuture(ConfirmResult.progress(CONFIRM_CLICKS - done));
        }
        pendingConfirms.remove(uuid);
        linkRequests.values().removeIf(r -> r.uuid().equals(uuid));
        finishing.put(uuid, pc);
        CompletableFuture<ConfirmResult> result = new CompletableFuture<>();
        Runnable cancelled = () -> {
            finishing.remove(uuid, pc);
            result.completeExceptionally(new IllegalStateException("2FA worker unavailable"));
        };
        if (!links.submit(() -> {
            ConfirmResult outcome;
            try {
                if (stopping || finishing.get(uuid) != pc || pc.expiresAt() <= System.currentTimeMillis()) {
                    outcome = ConfirmResult.none();
                } else {
                    List<String> backup = completeLink(pc);
                    outcome = backup == null ? ConfirmResult.none() : ConfirmResult.done(pc.provider(), backup);
                }
            } catch (RuntimeException failure) {
                finishing.remove(uuid, pc);
                result.completeExceptionally(failure);
                return;
            } finally {
                finishing.remove(uuid, pc);
            }
            result.complete(outcome);
        }, cancelled)) cancelled.run();
        return result;
    }

    public synchronized void cancelConfirm(UUID uuid) {
        pendingConfirms.remove(uuid);
        finishing.remove(uuid);
    }

    private List<String> completeLink(PendingConfirm pending) {
        UUID uuid = pending.uuid();
        Provider provider = pending.provider();
        String messengerId = pending.messengerId();
        List<String> backup = store.bind(uuid, provider, messengerId, backupCount,
                () -> !stopping && finishing.get(uuid) == pending && pending.expiresAt() > System.currentTimeMillis());
        if (backup == null) return null;
        synchronized (this) {
            if (stopping || finishing.get(uuid) != pending) return null;
            SetupSession session = pending.setupToken() == null ? null : setupSessions.get(pending.setupToken());
            if (session != null && session.uuid().equals(uuid) && session.expiresAt() > System.currentTimeMillis()) {
                freshBackup.put(uuid, backup);
            }
        }
        logger.info("2FA linked: " + pending.playerName() + " -> " + provider);
        return backup;
    }

    private Optional<String> findSetupToken(UUID uuid) {
        return setupSessions.entrySet().stream()
                .filter(e -> e.getValue().uuid().equals(uuid) && e.getValue().expiresAt() > System.currentTimeMillis())
                .map(Map.Entry::getKey)
                .findFirst();
    }

    public Optional<String> pendingLinkPlayer(String code) {
        LinkRequest r = linkRequests.get(code == null ? "" : code.trim().toUpperCase(Locale.ROOT));
        return r == null || r.expiresAt() <= System.currentTimeMillis()
                ? Optional.empty() : Optional.of(r.playerName());
    }

    public synchronized SetupOpen createSetup(UUID uuid, String playerName) {
        cancelSetup(uuid);
        setupSessions.values().removeIf(s -> s.uuid().equals(uuid));
        String code = createLinkCode(uuid, playerName);
        byte[] raw = new byte[SETUP_TOKEN_BYTES];
        RANDOM.nextBytes(raw);
        String sessionToken = HexFormat.of().formatHex(raw);
        long expires = System.currentTimeMillis() + linkTtlMillis;
        setupSessions.put(sessionToken, new SetupSession(uuid, playerName, code, expires));
        return new SetupOpen(sessionToken, code);
    }

    public record SetupOpen(String sessionToken, String linkCode) {}

    public synchronized Optional<SetupInfo> setupInfo(String sessionToken) {
        SetupSession s = setupSessions.get(sessionToken == null ? "" : sessionToken);
        if (s == null || s.expiresAt() <= System.currentTimeMillis()) {
            return Optional.empty();
        }
        return Optional.of(new SetupInfo(s.playerName(), s.linkCode(), s.expiresAt()));
    }

    public synchronized Optional<SetupStatus> setupStatus(String sessionToken) {
        SetupSession s = setupSessions.get(sessionToken == null ? "" : sessionToken);
        if (s == null || s.expiresAt() <= System.currentTimeMillis()) {
            return Optional.empty();
        }
        Optional<TwoFactorStore.Binding> binding = store.binding(s.uuid());
        boolean linked = !finishing.containsKey(s.uuid()) && binding.isPresent() && binding.get().linked();
        Provider provider = binding.map(TwoFactorStore.Binding::provider).orElse(null);
        List<String> backup = linked ? freshBackup.remove(s.uuid()) : null;
        boolean needsConfirm = hasPendingConfirm(s.uuid()) || finishing.containsKey(s.uuid());
        return Optional.of(new SetupStatus(linked, needsConfirm, provider, backup));
    }

    public Optional<String> requestLogin(UUID uuid, String playerName, String ip, Runnable onApprove, Runnable onDeny) {
        if (stopping) return Optional.empty();
        Optional<TwoFactorStore.Binding> binding = store.binding(uuid);
        if (binding.isEmpty() || !binding.get().linked()) {
            return Optional.empty();
        }
        TwoFactorStore.Binding b = binding.get();
        byte[] raw = new byte[TOKEN_BYTES];
        RANDOM.nextBytes(raw);
        String token = HexFormat.of().formatHex(raw);
        loginRequests.put(token, new LoginRequest(uuid, playerName, b.provider(), b.messengerId(), b, ip == null ? "unknown" : ip,
                System.currentTimeMillis() + confirmTtlMillis, onApprove, onDeny));
        if (!notifications.submit(() -> {
            LoginRequest current = loginRequests.get(token);
            if (stopping || current == null || current.expiresAt() <= System.currentTimeMillis()) return;
            try {
                dispatch(token, b.provider(), b.messengerId(), playerName, current.ip());
            } catch (RuntimeException failure) {
                logger.warning("2FA delivery failed: " + failure.getClass().getSimpleName());
                resolve(token, false);
            }
        })) {
            loginRequests.remove(token);
            return Optional.empty();
        }
        return Optional.of(token);
    }

    public Optional<String> requestLogin(UUID uuid, String playerName, Runnable onApprove, Runnable onDeny) {
        return requestLogin(uuid, playerName, "unknown", onApprove, onDeny);
    }

    private void dispatch(String token, Provider provider, String messengerId, String playerName, String ip) {
        switch (provider) {
            case DISCORD -> {
                if (discord != null) {
                    discord.sendConfirmation(messengerId, playerName, token, ip);
                } else {
                    throw new IllegalStateException("Discord bot unavailable");
                }
            }
            case TELEGRAM -> {
                if (telegram != null) {
                    telegram.sendConfirmation(messengerId, playerName, token, ip);
                } else {
                    throw new IllegalStateException("Telegram bot unavailable");
                }
            }
            case VK -> {
                if (vk != null) {
                    vk.sendConfirmation(messengerId, playerName, token, ip);
                } else {
                    throw new IllegalStateException("VK bot unavailable");
                }
            }
        }
    }

    boolean resolve(String token, boolean approved) {
        LoginRequest request = loginRequests.remove(token);
        if (request == null) return false;
        return finishLogin(token, approved, request);
    }

    private boolean finishLogin(String token, boolean approved, LoginRequest request) {
        clearPrompt(token);
        if (request.expiresAt() <= System.currentTimeMillis() || stopping
                || store.binding(request.uuid()).orElse(null) != request.binding()) {
            if (request.onDeny() != null) request.onDeny().run();
            return false;
        }
        Runnable action = approved ? request.onApprove() : request.onDeny();
        if (action != null) {
            action.run();
        }
        return true;
    }

    public boolean resolve(String token, boolean approved, Provider provider, String messengerId) {
        synchronized (store) {
            LoginRequest request = loginRequests.get(token);
            if (request == null || request.provider() != provider || !request.messengerId().equals(messengerId)) return false;
            return loginRequests.remove(token, request) && finishLogin(token, approved, request);
        }
    }

    public synchronized void cancelSetup(UUID uuid) {
        finishing.remove(uuid);
        pendingConfirms.remove(uuid);
        linkRequests.values().removeIf(r -> r.uuid().equals(uuid));
        setupSessions.values().removeIf(s -> s.uuid().equals(uuid));
        freshBackup.remove(uuid);
    }

    public void cancel(UUID uuid) {
        loginRequests.entrySet().removeIf(e -> e.getValue().uuid().equals(uuid));
        cleanupPrompts();
    }

    public boolean hasPendingLogin(UUID uuid) {
        return loginRequests.values().stream().anyMatch(r -> r.uuid().equals(uuid));
    }

    public void shutdown() {
        stopping = true;
        if (botAccounts != null) botAccounts.close();
        finishing.clear();
        loginRequests.clear();
        cleanupPrompts();
        notifications.close();
        links.close();
        setupSessions.clear();
        freshBackup.clear();
        linkRequests.clear();
        pendingConfirms.clear();
    }

    public synchronized void tick() {
        if (botAccounts != null) botAccounts.tick();
        long now = System.currentTimeMillis();
        linkRequests.values().removeIf(r -> r.expiresAt() <= now);
        setupSessions.values().removeIf(s -> s.expiresAt() <= now);
        pendingConfirms.values().removeIf(c -> c.expiresAt() <= now);
        freshBackup.keySet().removeIf(uuid -> setupSessions.values().stream().noneMatch(s -> s.uuid().equals(uuid)));
        loginRequests.entrySet().forEach(e -> {
            if (e.getValue().expiresAt() <= now && loginRequests.remove(e.getKey(), e.getValue())) {
                Runnable onDeny = e.getValue().onDeny();
                if (onDeny != null) {
                    onDeny.run();
                }
            }
        });
        cleanupPrompts();
    }
}
