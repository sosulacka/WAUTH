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

import mc.t1rei.wauth.twofa.Provider;
import mc.t1rei.wauth.twofa.TwoFactorManager;
import mc.t1rei.wauth.web.Json;
import mc.t1rei.wauth.core.BoundedExecutor;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.WebSocket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

public final class DiscordBot implements MessengerBot {

    private static final String API = "https://discord.com/api/v10";
    private static final String GATEWAY = "wss://gateway.discord.gg/?v=10&encoding=json";
    private static final int INTENT_DIRECT_MESSAGES = 1 << 12;
    private static final long RECONNECT_DELAY_MILLIS = 5000L;

    private final Logger logger;
    private final TwoFactorManager manager;
    private final String token;
    private final HttpClient http;

    private volatile boolean running;
    private volatile WebSocket socket;
    private volatile long heartbeatInterval;
    private volatile long lastSeq = -1;
    private volatile CompletableFuture<Void> closed;
    private volatile boolean heartbeatAcknowledged = true;

    private Thread supervisor;
    private Thread heartbeat;
    private final BoundedExecutor events = new BoundedExecutor("wauth-discord-events", 1, 128);
    private final Object sendLock = new Object();
    private final Map<String, String> dmChannels = new ConcurrentHashMap<>();

    public DiscordBot(Logger logger, TwoFactorManager manager, String token) {
        this(logger, manager, token, HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());
    }

    DiscordBot(Logger logger, TwoFactorManager manager, String token, HttpClient http) {
        this.logger = logger;
        this.manager = manager;
        this.token = token;
        this.http = http;
    }

    @Override
    public void start() {
        if (token == null || token.isBlank()) {
            logger.warning("Discord: токен не задан — бот не запущен.");
            return;
        }
        running = true;
        supervisor = new Thread(this::connectLoop, "wauth-discord");
        supervisor.setDaemon(true);
        supervisor.start();
        logger.info("Discord-бот 2FA запущен.");
    }

    @Override
    public void stop() {
        running = false;
        stopHeartbeat();
        WebSocket ws = socket;
        if (ws != null) {
            try {
                ws.sendClose(WebSocket.NORMAL_CLOSURE, "shutdown");
            } catch (RuntimeException ignored) {
            }
        }
        if (supervisor != null) {
            supervisor.interrupt();
        }
        events.close();
    }

    @Override
    public void sendConfirmation(String messengerId, String playerName, String token) {
        sendConfirmation(messengerId, playerName, token, "unknown");
    }

    @Override
    public void sendConfirmation(String messengerId, String playerName, String token, String ip) {
        sendMessage(messengerId, BotReply.login(playerName, ip, token));
    }

    @Override
    public void sendMessage(String messengerId, BotReply reply) {
        String channel = openDm(messengerId).orElseThrow(() -> new IllegalStateException("Discord DM unavailable"));
        sendReply(channel, reply);
    }

    private void sendReply(String channel, BotReply reply) {
        Json.Writer body = Json.object().put("content", reply.text()).put("allowed_mentions", Json.object().put("parse", List.of()));
        if (!reply.buttons().isEmpty()) {
            body.put("components", List.of(Json.object().put("type", 1).put("components", reply.buttons().stream()
                    .map(button -> Json.object().put("type", 2).put("style", 2)
                            .put("label", button.label()).put("custom_id", button.action())).toList())));
        }
        String response = rest("POST", "/channels/" + channel + "/messages", body.build(), true)
                .orElseThrow(() -> new IllegalStateException("Discord delivery failed"));
        if (reply.promptToken() != null) {
            String messageId = str(Json.parseObject(response).get("id"));
            manager.trackPrompt(reply.promptToken(), () -> {
                if (rest("DELETE", "/channels/" + channel + "/messages/" + messageId, "", true).isEmpty()) {
                    rest("PATCH", "/channels/" + channel + "/messages/" + messageId,
                            Json.object().put("content", "Запрос закрыт.").put("components", List.of()).build(), true);
                }
            });
        }
    }

    private Optional<String> openDm(String userId) {
        String cached = dmChannels.get(userId);
        if (cached != null) {
            return Optional.of(cached);
        }
        String body = Json.object().put("recipient_id", userId).build();
        Optional<String> response = rest("POST", "/users/@me/channels", body, true);
        if (response.isEmpty()) {
            return Optional.empty();
        }
        String id = str(Json.parseObject(response.get()).get("id"));
        if (id.isEmpty()) {
            return Optional.empty();
        }
        if (dmChannels.size() < 10_000) dmChannels.put(userId, id);
        return Optional.of(id);
    }

    private void connectLoop() {
        while (running) {
            try {
                connectOnce();
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception failure) {
                logger.warning("Discord: соединение прервано: " + failure);
            } finally {
                stopHeartbeat();
                socket = null;
            }
            if (!running) {
                return;
            }
            try {
                Thread.sleep(RECONNECT_DELAY_MILLIS);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private void connectOnce() throws Exception {
        lastSeq = -1;
        CompletableFuture<Void> done = new CompletableFuture<>();
        closed = done;
        WebSocket ws = http.newWebSocketBuilder()
                .buildAsync(URI.create(GATEWAY), new GatewayListener(done))
                .get(20, TimeUnit.SECONDS);
        socket = ws;
        done.get();
    }

    private void sendIdentify() {
        String payload = Json.object()
                .put("op", 2)
                .put("d", Json.object()
                        .put("token", token)
                        .put("intents", INTENT_DIRECT_MESSAGES)
                        .put("properties", Json.object()
                                .put("os", "linux")
                                .put("browser", "wauth")
                                .put("device", "wauth")))
                .build();
        sendJson(payload);
    }

    private void startHeartbeat() {
        stopHeartbeat();
        heartbeatAcknowledged = true;
        heartbeat = new Thread(() -> {
            try {
                Thread.sleep((long) (heartbeatInterval * Math.random()));
                while (running && socket != null) {
                    if (!heartbeatAcknowledged) {
                        reconnect();
                        return;
                    }
                    heartbeatAcknowledged = false;
                    sendHeartbeat();
                    Thread.sleep(heartbeatInterval);
                }
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
        }, "wauth-discord-heartbeat");
        heartbeat.setDaemon(true);
        heartbeat.start();
    }

    private void stopHeartbeat() {
        Thread hb = heartbeat;
        if (hb != null) {
            hb.interrupt();
            heartbeat = null;
        }
    }

    private void sendHeartbeat() {
        sendJson(Json.object().put("op", 1).put("d", lastSeq < 0 ? null : lastSeq).build());
    }

    private void sendJson(String payload) {
        WebSocket ws = socket;
        if (ws == null) {
            return;
        }
        synchronized (sendLock) {
            try {
                ws.sendText(payload, true).get(10, TimeUnit.SECONDS);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            } catch (Exception failure) {
                logger.warning("Discord: отправка не удалась: " + failure);
            }
        }
    }

    private void process(String message) {
        Map<String, Object> root;
        try {
            root = Json.parseObject(message);
        } catch (RuntimeException malformed) {
            return;
        }
        Object seq = root.get("s");
        if (seq instanceof Number n) {
            lastSeq = n.longValue();
        }
        int op = (int) asLong(root.get("op"));
        switch (op) {
            case 10 -> {
                Object d = root.get("d");
                if (d instanceof Map<?, ?> hello) {
                    heartbeatInterval = Math.max(1000, asLong(hello.get("heartbeat_interval")));
                    startHeartbeat();
                    sendIdentify();
                }
            }
            case 1 -> sendHeartbeat();
            case 11 -> heartbeatAcknowledged = true;
            case 7, 9 -> reconnect();
            case 0 -> {
                if (!events.submit(() -> dispatch(str(root.get("t")), root.get("d")))) reconnect();
            }
            default -> {
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void dispatch(String type, Object data) {
        if (!(data instanceof Map)) {
            return;
        }
        Map<String, Object> d = (Map<String, Object>) data;
        if ("MESSAGE_CREATE".equals(type)) {
            handleMessage(d);
        } else if ("INTERACTION_CREATE".equals(type)) {
            handleInteraction(d);
        }
    }

    @SuppressWarnings("unchecked")
    private void handleMessage(Map<String, Object> message) {
        if (message.get("guild_id") != null) {
            return;
        }
        Object authorRaw = message.get("author");
        if (!(authorRaw instanceof Map)) {
            return;
        }
        Map<String, Object> author = (Map<String, Object>) authorRaw;
        if (Boolean.TRUE.equals(author.get("bot"))) {
            return;
        }
        String userId = str(author.get("id"));
        String channelId = str(message.get("channel_id"));
        String code = str(message.get("content")).trim();
        if (userId.isEmpty() || channelId.isEmpty() || code.isEmpty()) {
            return;
        }
        if (code.matches("(?is)^/?(password|changepass)\\b.*")) {
            sendReply(channelId, BotReply.menu("Для смены пароля нажмите «Сменить пароль» и заполните форму. "
                    + "Если вы уже отправили пароль сообщением, удалите его: Discord не разрешает боту удалять ваши личные сообщения."));
            return;
        }
        manager.handleBotCommand(Provider.DISCORD, userId, code).thenAccept(reply -> sendReply(channelId, reply));
    }

    @SuppressWarnings("unchecked")
    private void handleInteraction(Map<String, Object> interaction) {
        long type = asLong(interaction.get("type"));
        if (interaction.get("guild_id") != null || (type != 3 && type != 5)) {
            return;
        }
        String id = str(interaction.get("id"));
        String interactionToken = str(interaction.get("token"));
        Object dataRaw = interaction.get("data");
        String customId = dataRaw instanceof Map ? str(((Map<String, Object>) dataRaw).get("custom_id")) : "";
        String userId = interactionUser(interaction);
        if (userId.isEmpty()) return;
        if (type == 3 && customId.equals("password")) {
            respondInteractionBody(id, interactionToken, Json.object().put("type", 9).put("data", Json.object()
                    .put("custom_id", "password-form").put("title", "Смена пароля WAUTH")
                    .put("components", List.of(passwordField("current", "Текущий пароль"), passwordField("new", "Новый пароль")))).build());
            return;
        }
        String command = customId;
        if (type == 5) {
            if (!customId.equals("password-form") || !(dataRaw instanceof Map<?, ?> data)) return;
            Map<String, String> values = new java.util.HashMap<>();
            if (data.get("components") instanceof List<?> rows) for (Object row : rows) {
                if (row instanceof Map<?, ?> r && r.get("components") instanceof List<?> fields) for (Object field : fields) {
                    if (field instanceof Map<?, ?> f) values.put(str(f.get("custom_id")), str(f.get("value")));
                }
            }
            command = "/password " + values.getOrDefault("current", "") + " " + values.getOrDefault("new", "");
        }
        respondInteraction(id, interactionToken, "Запрос принят. Результат придёт в личные сообщения.");
        manager.handleBotCommand(Provider.DISCORD, userId, command).thenAccept(reply -> sendMessage(userId, reply));
    }

    private Json.Writer passwordField(String id, String label) {
        return Json.object().put("type", 1).put("components", List.of(Json.object().put("type", 4)
                .put("custom_id", id).put("label", label).put("style", 1).put("required", true).put("max_length", 72)));
    }

    @SuppressWarnings("unchecked")
    private String interactionUser(Map<String, Object> interaction) {
        Object user = interaction.get("user");
        if (user instanceof Map) {
            return str(((Map<String, Object>) user).get("id"));
        }
        Object member = interaction.get("member");
        if (member instanceof Map && ((Map<String, Object>) member).get("user") instanceof Map<?, ?> nested) {
            return str(nested.get("id"));
        }
        return "";
    }

    private void respondInteraction(String id, String interactionToken, String text) {
        String body = Json.object()
                .put("type", 4)
                .put("data", Json.object().put("content", text).put("flags", 64))
                .build();
        respondInteractionBody(id, interactionToken, body);
    }

    private void respondInteractionBody(String id, String interactionToken, String body) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(API + "/interactions/" + id + "/" + interactionToken + "/callback"))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                    .build();
            http.send(request, HttpResponse.BodyHandlers.discarding());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        } catch (Exception failure) {
            logger.warning("Discord interaction response failed: " + failure.getClass().getSimpleName());
        }
    }

    private void reconnect() {
        WebSocket ws = socket;
        if (ws != null) {
            try {
                ws.sendClose(WebSocket.NORMAL_CLOSURE, "reconnect");
            } catch (RuntimeException ignored) {
            }
        }
        CompletableFuture<Void> done = closed;
        if (done != null) {
            done.complete(null);
        }
    }

    private Optional<String> rest(String method, String path, String body, boolean auth) {
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder()
                    .uri(URI.create(API + path))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "application/json");
            if (auth) {
                builder.header("Authorization", "Bot " + token);
            }
            HttpRequest request = builder
                    .method(method, HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() / 100 != 2) {
                logger.warning("Discord: " + method + " " + path + " вернул " + response.statusCode());
                return Optional.empty();
            }
            return Optional.of(response.body());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        } catch (Exception failure) {
            logger.warning("Discord: " + method + " " + path + " не отправлен: " + failure);
            return Optional.empty();
        }
    }

    private final class GatewayListener implements WebSocket.Listener {
        private final StringBuilder buffer = new StringBuilder();
        private final CompletableFuture<Void> done;

        private GatewayListener(CompletableFuture<Void> done) {
            this.done = done;
        }

        @Override
        public void onOpen(WebSocket webSocket) {
            socket = webSocket;
            webSocket.request(1);
        }

        @Override
        public CompletableFuture<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
            if (buffer.length() + data.length() > 1024 * 1024) {
                buffer.setLength(0);
                webSocket.abort();
                done.complete(null);
                return null;
            }
            buffer.append(data);
            if (last) {
                String message = buffer.toString();
                buffer.setLength(0);
                try {
                    process(message);
                } catch (RuntimeException rejected) {
                    logger.warning("Discord: событие отброшено: " + rejected);
                }
            }
            webSocket.request(1);
            return null;
        }

        @Override
        public CompletableFuture<?> onClose(WebSocket webSocket, int statusCode, String reason) {
            done.complete(null);
            return null;
        }

        @Override
        public void onError(WebSocket webSocket, Throwable error) {
            done.complete(null);
        }
    }

    private static long asLong(Object value) {
        return value instanceof Number n ? n.longValue() : 0L;
    }

    private static String str(Object value) {
        return value == null ? "" : value.toString();
    }
}
