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

package mc.t1rei.wauth.twofa.messenger;

import mc.t1rei.wauth.PlayerStore;
import mc.t1rei.wauth.twofa.Provider;
import mc.t1rei.wauth.twofa.TwoFactorManager;
import mc.t1rei.wauth.twofa.TwoFactorStore;
import mc.t1rei.wauth.web.Json;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import java.net.*;
import java.net.http.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

class MessengerTransportTest {
    @TempDir Path dir;
    final Logger log = Logger.getLogger("MessengerTransportTest");
    final UUID player = UUID.randomUUID();

    private TwoFactorManager manager(Provider provider) throws Exception {
        Files.createDirectories(dir.resolve("data"));
        Files.writeString(dir.resolve("data/twofa.db"), "CC1P:" + player + "\ttrue\t" + provider + "\t123\t\t1\n");
        TwoFactorStore store = new TwoFactorStore(dir, new PlayerStore(dir, null, log), log, false, null);
        store.load();
        return new TwoFactorManager(log, store, 60_000, 60_000, 1);
    }

    @Test void everyTransportIncludesIpAndRemovesConsumedPrompt() throws Exception {
        for (Provider provider : Provider.values()) {
            TwoFactorManager manager = manager(provider);
            FakeHttp http = new FakeHttp();
            MessengerBot bot = switch (provider) {
                case TELEGRAM -> new TelegramBot(log, manager, "secret", http);
                case VK -> new VkBot(log, manager, "secret", 1, http);
                case DISCORD -> new DiscordBot(log, manager, "secret", http);
            };
            manager.attachBots(provider == Provider.TELEGRAM ? bot : null, provider == Provider.VK ? bot : null,
                    provider == Provider.DISCORD ? bot : null);
            try {
                AtomicInteger approved = new AtomicInteger();
                String token = manager.requestLogin(player, "Player", "2001:db8::9", approved::incrementAndGet, () -> {}).orElseThrow();
                await(() -> http.calls.stream().anyMatch(c -> c.decoded().contains("2001:db8::9")));
                assertEquals(32, token.length());
                assertTrue(manager.handleBotCommand(provider, "123", "approve:" + token).join().text().contains("2001:db8::9"));
                assertEquals(1, approved.get());
                await(() -> http.calls.stream().anyMatch(c -> c.method().equals("DELETE") || c.path().endsWith("deleteMessage")
                        || c.path().endsWith("messages.delete")));
                manager.notifyLogin(player, "Player", "203.0.113.5");
                await(() -> http.calls.stream().anyMatch(c -> c.decoded().contains("203.0.113.5")));
                assertTrue(http.calls.stream().anyMatch(c -> c.decoded().contains("Вход выполнен")));
            } finally { manager.shutdown(); bot.stop(); }
        }
    }

    @Test void publicMessagesAndCallbacksDoNotReachAccountCommands() throws Exception {
        TwoFactorManager manager = manager(Provider.VK);
        FakeHttp http = new FakeHttp();
        VkBot vk = new VkBot(log, manager, "secret", 1, http);
        TelegramBot tg = new TelegramBot(log, manager, "secret", http);
        DiscordBot discord = new DiscordBot(log, manager, "secret", http);
        try {
            invoke(vk, "handleMessage", Map.of("from_id", 123, "peer_id", 2000000001, "text", "/lock"));
            invoke(vk, "handleCallback", Map.of("user_id", 123, "peer_id", 2000000001, "event_id", "x", "payload", Map.of("cmd", "lock")));
            invoke(tg, "handleMessage", Map.of("from", Map.of("id", 123), "chat", Map.of("id", -10, "type", "group"), "text", "/lock"));
            invoke(tg, "handleCallback", Map.of("id", "x", "from", Map.of("id", 123), "data", "lock",
                    "message", Map.of("chat", Map.of("id", -10, "type", "group"))));
            invoke(discord, "handleMessage", Map.of("guild_id", "1", "author", Map.of("id", "123"), "channel_id", "10", "content", "/lock"));
            invoke(discord, "handleInteraction", Map.of("guild_id", "1", "type", 3, "user", Map.of("id", "123"), "data", Map.of("custom_id", "lock")));
            assertTrue(http.calls.isEmpty());
        } finally { manager.shutdown(); discord.stop(); }
    }

    @Test void discordPasswordButtonOpensFormWithoutPostingSecrets() throws Exception {
        TwoFactorManager manager = manager(Provider.DISCORD);
        FakeHttp http = new FakeHttp();
        DiscordBot discord = new DiscordBot(log, manager, "secret", http);
        try {
            invoke(discord, "handleInteraction", Map.of("type", 3, "id", "1", "token", "interaction-secret",
                    "user", Map.of("id", "123"), "data", Map.of("custom_id", "password")));
            assertEquals(1, http.calls.size());
            Map<String, Object> body = Json.parseObject(http.calls.getFirst().body());
            assertEquals(9L, ((Number) body.get("type")).longValue());
            assertTrue(http.calls.getFirst().body().contains("password-form"));
            assertTrue(http.calls.getFirst().path().endsWith("/callback"));
        } finally { manager.shutdown(); discord.stop(); }
    }

    private static void invoke(Object target, String method, Map<String, Object> data) throws Exception {
        var handler = target.getClass().getDeclaredMethod(method, Map.class);
        handler.setAccessible(true);
        handler.invoke(target, data);
    }

    private static void await(BooleanSupplier condition) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!condition.getAsBoolean() && System.nanoTime() < deadline) Thread.sleep(5);
        assertTrue(condition.getAsBoolean(), "Expected transport operation was not issued");
    }

    record Call(String method, String path, String body) {
        String decoded() { return path.startsWith("/method/") ? URLDecoder.decode(body, StandardCharsets.UTF_8) : body; }
    }

    static final class FakeHttp extends HttpClient {
        final List<Call> calls = new CopyOnWriteArrayList<>();
        @Override @SuppressWarnings("unchecked") public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> handler) {
            StringBuilder body = new StringBuilder();
            request.bodyPublisher().ifPresent(p -> p.subscribe(new Flow.Subscriber<>() {
                public void onSubscribe(Flow.Subscription subscription) { subscription.request(Long.MAX_VALUE); }
                public void onNext(ByteBuffer item) { body.append(StandardCharsets.UTF_8.decode(item)); }
                public void onError(Throwable error) { throw new AssertionError(error); }
                public void onComplete() { }
            }));
            calls.add(new Call(request.method(), request.uri().getPath(), body.toString()));
            String response = request.uri().getHost().contains("telegram")
                    ? "{\"ok\":true,\"result\":{\"message_id\":42}}"
                    : request.uri().getHost().contains("vk.com") ? "{\"response\":42}" : "{\"id\":\"42\"}";
            return new HttpResponse<>() {
                public int statusCode() { return 200; }
                public HttpRequest request() { return request; }
                public Optional<HttpResponse<T>> previousResponse() { return Optional.empty(); }
                public HttpHeaders headers() { return HttpHeaders.of(Map.of(), (a, b) -> true); }
                public T body() { return (T) response; }
                public Optional<SSLSession> sslSession() { return Optional.empty(); }
                public URI uri() { return request.uri(); }
                public Version version() { return Version.HTTP_1_1; }
            };
        }
        public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest r, HttpResponse.BodyHandler<T> h) { return CompletableFuture.completedFuture(send(r, h)); }
        public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest r, HttpResponse.BodyHandler<T> h, HttpResponse.PushPromiseHandler<T> p) { return sendAsync(r, h); }
        public Optional<CookieHandler> cookieHandler() { return Optional.empty(); }
        public Optional<Duration> connectTimeout() { return Optional.empty(); }
        public Redirect followRedirects() { return Redirect.NEVER; }
        public Optional<ProxySelector> proxy() { return Optional.empty(); }
        public SSLContext sslContext() { try { return SSLContext.getDefault(); } catch (Exception e) { throw new AssertionError(e); } }
        public SSLParameters sslParameters() { return new SSLParameters(); }
        public Optional<Authenticator> authenticator() { return Optional.empty(); }
        public Version version() { return Version.HTTP_1_1; }
        public Optional<Executor> executor() { return Optional.empty(); }
    }
}
