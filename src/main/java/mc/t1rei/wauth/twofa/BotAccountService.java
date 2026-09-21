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

import mc.t1rei.wauth.PlayerStore;
import mc.t1rei.wauth.core.AttemptLimiter;
import mc.t1rei.wauth.core.BoundedExecutor;
import mc.t1rei.wauth.twofa.messenger.BotReply;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiFunction;
import java.util.function.Consumer;

public final class BotAccountService implements AutoCloseable {
    private record Action(TwoFactorStore.Binding binding, PlayerStore.Account account, String kind,
                          String newHash, long expiresAt) {}
    private final PlayerStore accounts;
    private final TwoFactorStore bindings;
    private final BiFunction<String, String, String> passwordError;
    private final Consumer<UUID> revokeSessions;
    private final BoundedExecutor workers = new BoundedExecutor("wauth-bot-account", 2, 32);
    private final AttemptLimiter attempts = new AttemptLimiter(5, 5, 300_000, 20_000);
    private final Map<String, Action> actions = new ConcurrentHashMap<>();
    private final long ttl;
    private volatile boolean closed;

    public BotAccountService(PlayerStore accounts, TwoFactorStore bindings,
                             BiFunction<String, String, String> passwordError, Consumer<UUID> revokeSessions, long ttl) {
        this.accounts = accounts;
        this.bindings = bindings;
        this.passwordError = passwordError;
        this.revokeSessions = revokeSessions;
        this.ttl = ttl;
    }

    public CompletableFuture<BotReply> handle(Provider provider, String id, String input) {
        CompletableFuture<BotReply> result = new CompletableFuture<>();
        Runnable unavailable = () -> result.complete(BotReply.text("Сервис занят. Повторите позже."));
        if (closed || provider == null || id == null || !id.matches("[1-9][0-9]{0,24}")
                || input == null || input.length() > 512 || !workers.submit(() -> {
            try { result.complete(execute(provider, id, input)); }
            catch (RuntimeException failure) { result.complete(BotReply.text("Операция не выполнена. Повторите позже.")); }
        }, unavailable)) unavailable.run();
        return result;
    }

    private BotReply execute(Provider provider, String id, String input) {
        if (closed) return BotReply.text("Сервис остановлен.");
        TwoFactorStore.Binding binding = bindings.byMessenger(provider, id).orElse(null);
        PlayerStore.Account account = binding == null ? null : accounts.byUuid(binding.uuid()).orElse(null);
        if (account == null) return BotReply.text("Сначала привяжите аккаунт: /2fa link в игре, затем отправьте код сюда.");
        String[] words = input.strip().split("\\s+");
        String command = words[0].replaceFirst("^/", "").toLowerCase(java.util.Locale.ROOT);
        if (command.startsWith("confirm:") || command.startsWith("cancel:")) {
            return finish(binding, command.substring(command.indexOf(':') + 1), command.startsWith("confirm:"));
        }
        if (command.equals("confirm") || command.equals("cancel")) {
            if (words.length == 2) return finish(binding, words[1], command.equals("confirm"));
            if (command.equals("cancel")) {
                actions.values().removeIf(a -> a.binding().uuid().equals(binding.uuid()));
                return BotReply.menu("Запросы управления аккаунтом отменены.");
            }
            return BotReply.text("Используйте кнопку подтверждения в запросе.");
        }
        if (command.equals("status") || command.equals("menu") || command.equals("start")) {
            return BotReply.menu("Аккаунт: " + account.name() + "\nСтатус: " + (account.locked() ? "заблокирован" : "доступен")
                    + "\n2FA: " + (binding.enabled() ? "включена" : "выключена")
                    + "\nРезервных кодов: " + binding.backupHashes().size()
                    + "\nПоследний вход: " + (account.lastLoginAt() == 0 ? "нет" : Instant.ofEpochMilli(account.lastLoginAt()))
                    + "\nIP последнего входа: " + (account.lastIp() == null || account.lastIp().isBlank() ? "нет" : account.lastIp()));
        }
        if (command.equals("password") || command.equals("changepass")) {
            if (words.length != 3) return BotReply.text("Для смены: /password <текущий_пароль> <новый_пароль>\n"
                    + "Пишите только в личные сообщения. Затем подтвердите действие кнопкой. "
                    + "Бот попытается удалить сообщение; если оно осталось, удалите его вручную. В Discord используйте кнопку и форму. "
                    + "Не используйте пароль от почты или мессенджера.");
            if (!allowed(account, provider, id)) return BotReply.text("Слишком много попыток. Подождите 5 минут.");
            String error = passwordError.apply(account.name(), words[2]);
            if (error != null) return BotReply.text(error);
            char[] old = words[1].toCharArray();
            char[] fresh = words[2].toCharArray();
            try {
                if (!accounts.verify(old, account.hash())) return BotReply.text("Текущий пароль неверен.");
                if (words[1].equals(words[2])) return BotReply.text("Новый пароль должен отличаться от текущего.");
                return prepare(binding, account, "password", accounts.hash(fresh),
                        "Сменить пароль аккаунта " + account.name() + "? Текущая игровая сессия будет завершена.");
            } finally {
                java.util.Arrays.fill(old, '\0');
                java.util.Arrays.fill(fresh, '\0');
                java.util.Arrays.fill(words, "");
            }
        }
        if (command.equals("lock") || command.equals("ban") || command.equals("unlock")) {
            if (!allowed(account, provider, id)) return BotReply.text("Слишком много запросов. Подождите 5 минут.");
            boolean lock = !command.equals("unlock");
            if (account.locked() == lock) return BotReply.menu(lock ? "Аккаунт уже заблокирован." : "Аккаунт уже разблокирован.");
            return prepare(binding, account, lock ? "lock" : "unlock", null,
                    (lock ? "Заблокировать " : "Разблокировать ") + account.name() + "?\n"
                            + (lock ? "Игрок будет отключён. Вход запрещён до /unlock в этом боте." : "Вход снова будет разрешён после пароля и 2FA."));
        }
        return BotReply.menu("WAUTH: управление вашим игровым аккаунтом.\n/status - статус и последний IP\n"
                + "/lock (или /ban) - заблокировать\n/unlock - разблокировать\n/password - сменить пароль\n/cancel - отменить запрос\n"
                + "Незнакомый IP? Отклоните вход, заблокируйте аккаунт и смените пароль.");
    }

    private boolean allowed(PlayerStore.Account account, Provider provider, String id) {
        return attempts.acquire(account.uuid(), provider + ":" + id) == 0;
    }

    private synchronized BotReply prepare(TwoFactorStore.Binding binding, PlayerStore.Account account,
                                           String kind, String newHash, String text) {
        if (closed || bindings.binding(account.uuid()).orElse(null) != binding) return BotReply.text("Привязка изменилась. Повторите команду.");
        actions.values().removeIf(a -> a.binding().uuid().equals(account.uuid()) || a.expiresAt() <= System.currentTimeMillis());
        if (actions.size() >= 1024) return BotReply.text("Сервис занят. Повторите позже.");
        byte[] random = new byte[16];
        new SecureRandom().nextBytes(random);
        String token = HexFormat.of().formatHex(random);
        actions.put(token, new Action(binding, account, kind, newHash, System.currentTimeMillis() + ttl));
        return BotReply.confirm(text + "\nЗапрос действует " + Math.max(1, ttl / 1000) + " сек.", token);
    }

    private BotReply finish(TwoFactorStore.Binding binding, String token, boolean approve) {
        Action action = actions.get(token);
        if (action == null || action.binding() != binding || !actions.remove(token, action))
            return BotReply.text("Запрос истёк или уже обработан.");
        if (!approve) return BotReply.menu("Действие отменено.");
        synchronized (bindings) {
            if (closed || action.expiresAt() <= System.currentTimeMillis()
                    || bindings.binding(binding.uuid()).orElse(null) != binding)
                return BotReply.text("Запрос истёк или привязка изменилась.");
            synchronized (accounts) {
                PlayerStore.Account current = accounts.byUuid(binding.uuid()).orElse(null);
                if (current == null || !current.hash().equals(action.account().hash()) || current.locked() != action.account().locked())
                    return BotReply.text("Аккаунт изменился. Повторите команду.");
                boolean changed = action.kind().equals("password")
                        ? accounts.updateHash(current, action.newHash()) : accounts.setLocked(current, action.kind().equals("lock"));
                if (!changed) return BotReply.text("Аккаунт изменился. Повторите команду.");
                accounts.save();
                revokeSessions.accept(binding.uuid());
            }
        }
        return BotReply.menu(switch (action.kind()) {
            case "password" -> "Пароль изменён. Игровые сессии отозваны.";
            case "lock" -> "Аккаунт заблокирован. Для разблокировки: /unlock.";
            default -> "Аккаунт разблокирован. Войдите заново.";
        });
    }

    public boolean pending(String token) {
        Action action = actions.get(token);
        return action != null && action.expiresAt() > System.currentTimeMillis()
                && bindings.binding(action.binding().uuid()).orElse(null) == action.binding();
    }

    public void tick() { actions.keySet().removeIf(token -> !pending(token)); }
    @Override public void close() { closed = true; actions.clear(); workers.close(); }
}
