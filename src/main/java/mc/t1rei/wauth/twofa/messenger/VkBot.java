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

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;
import java.util.logging.Logger;

public final class VkBot implements MessengerBot {

    private static final String API = "https://api.vk.com/method/";
    private static final String API_VERSION = "5.199";

    private final Logger logger;
    private final TwoFactorManager manager;
    private final String token;
    private final long groupId;
    private final HttpClient http;

    private volatile boolean running;
    private Thread worker;

    public VkBot(Logger logger, TwoFactorManager manager, String token, long groupId) {
        this(logger, manager, token, groupId, HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());
    }

    VkBot(Logger logger, TwoFactorManager manager, String token, long groupId, HttpClient http) {
        this.logger = logger;
        this.manager = manager;
        this.token = token;
        this.groupId = groupId;
        this.http = http;
    }

    @Override
    public void start() {
        if (token == null || token.isBlank() || groupId <= 0) {
            logger.warning("VK: токен/group-id не заданы — бот не запущен.");
            return;
        }
        running = true;
        worker = new Thread(this::loop, "wauth-vk");
        worker.setDaemon(true);
        worker.start();
        logger.info("VK-бот 2FA запущен.");
    }

    @Override
    public void stop() {
        running = false;
        if (worker != null) {
            worker.interrupt();
        }
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
        var rows = reply.buttons().stream().map(b -> List.of(button(b.label(), "secondary", b.action()))).toList();
        Map<String, String> params = new java.util.HashMap<>(Map.of(
                "user_id", messengerId,
                "random_id", String.valueOf(ThreadLocalRandom.current().nextInt()),
                "message", reply.text()));
        if (!rows.isEmpty()) params.put("keyboard", Json.object().put("inline", true).put("buttons", rows).build());
        String response = method("messages.send", params).orElseThrow(() -> new IllegalStateException("VK delivery failed"));
        if (reply.promptToken() != null) {
            Object value = Json.parseObject(response).get("response");
            String messageId = str(value);
            manager.trackPrompt(reply.promptToken(), () -> {
                if (!deleteMessage(messengerId, messageId)) method("messages.edit", Map.of("peer_id", messengerId,
                        "message_id", messageId, "message", "Запрос закрыт.", "keyboard", Json.object()
                                .put("inline", true).put("buttons", List.of()).build()));
            });
        }
    }

    private boolean deleteMessage(String peer, String messageId) {
        Optional<String> response = method("messages.delete", Map.of("peer_id", peer,
                "message_ids", messageId, "delete_for_all", "1", "group_id", String.valueOf(groupId)));
        if (response.isEmpty()) return false;
        Object result = Json.parseObject(response.get()).get("response");
        return result instanceof Map<?, ?> statuses && statuses.get(messageId) instanceof Number status && status.intValue() == 1;
    }

    private Json.Writer button(String label, String color, String payload) {
        return Json.object()
                .put("action", Json.object()
                        .put("type", "callback")
                        .put("label", label)
                        .put("payload", new Json.Raw(Json.object().put("cmd", payload).build())))
                .put("color", color);
    }

    private void loop() {
        while (running) {
            try {
                LongPoll lp = openLongPoll();
                if (lp == null) {
                    Thread.sleep(5000);
                    continue;
                }
                String ts = lp.ts();
                while (running) {
                    Optional<String> response = poll(lp, ts);
                    if (response.isEmpty()) {
                        break;
                    }
                    ts = handleEvents(response.get(), ts);
                    if (ts == null) {
                        break;
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                logger.warning("VK polling failed: " + e.getClass().getSimpleName());
                sleepQuietly();
            }
        }
    }

    private record LongPoll(String server, String key, String ts) {}

    @SuppressWarnings("unchecked")
    private LongPoll openLongPoll() {
        Optional<String> response = method("groups.getLongPollServer", Map.of("group_id", String.valueOf(groupId)));
        if (response.isEmpty()) {
            return null;
        }
        Map<String, Object> root = Json.parseObject(response.get());
        if (!(root.get("response") instanceof Map)) {
            logger.warning("VK: unexpected getLongPollServer response");
            return null;
        }
        Map<String, Object> r = (Map<String, Object>) root.get("response");
        return new LongPoll(str(r.get("server")), str(r.get("key")), str(r.get("ts")));
    }

    private Optional<String> poll(LongPoll lp, String ts) {
        try {
            String url = lp.server() + "?act=a_check&key=" + enc(lp.key()) + "&ts=" + enc(ts) + "&wait=25";
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(35))
                    .GET()
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return response.statusCode() / 100 == 2 ? Optional.of(response.body()) : Optional.empty();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        } catch (Exception e) {
            logger.warning("VK polling failed: " + e.getClass().getSimpleName());
            return Optional.empty();
        }
    }

    @SuppressWarnings("unchecked")
    private String handleEvents(String json, String currentTs) {
        Map<String, Object> root = Json.parseObject(json);
        if (root.get("failed") != null) {
            return null;
        }
        String ts = root.get("ts") == null ? currentTs : str(root.get("ts"));
        if (root.get("updates") instanceof List<?> updates) {
            for (Object u : updates) {
                if (u instanceof Map) {
                    handleEvent((Map<String, Object>) u);
                }
            }
        }
        return ts;
    }

    @SuppressWarnings("unchecked")
    private void handleEvent(Map<String, Object> event) {
        String type = str(event.get("type"));
        Object objRaw = event.get("object");
        if (!(objRaw instanceof Map)) {
            return;
        }
        Map<String, Object> object = (Map<String, Object>) objRaw;
        switch (type) {
            case "message_new" -> {
                Object msg = object.get("message");
                if (msg instanceof Map) {
                    handleMessage((Map<String, Object>) msg);
                }
            }
            case "message_event" -> handleCallback(object);
            default -> { }
        }
    }

    private void handleMessage(Map<String, Object> message) {
        String userId = str(message.get("from_id"));
        String text = str(message.get("text")).trim();
        if (!userId.matches("[1-9][0-9]{0,24}") || !userId.equals(str(message.get("peer_id")))
                || text.isEmpty() || "1".equals(str(message.get("out")))) {
            return;
        }
        if (text.matches("(?is)^/?(password|changepass)\\b.*")) {
            String messageId = str(message.get("id"));
            if (messageId.isBlank() || !deleteMessage(userId, messageId))
                sendMessage(userId, BotReply.text("VK не позволил удалить ваше сообщение с паролем. Удалите его вручную у всех участников."));
        }
        manager.handleBotCommand(Provider.VK, userId, text).thenAccept(result -> sendMessage(userId, result));
    }

    @SuppressWarnings("unchecked")
    private void handleCallback(Map<String, Object> object) {
        String userId = str(object.get("user_id"));
        String peerId = str(object.get("peer_id"));
        String eventId = str(object.get("event_id"));
        Object payloadRaw = object.get("payload");
        String cmd = payloadRaw instanceof Map ? str(((Map<String, Object>) payloadRaw).get("cmd")) : "";
        if (!userId.matches("[1-9][0-9]{0,24}") || !userId.equals(peerId)) return;
        String eventData = Json.object().put("type", "show_snackbar").put("text", "Обрабатываю запрос...").build();
        method("messages.sendMessageEventAnswer", Map.of("event_id", eventId, "user_id", userId,
                "peer_id", peerId, "event_data", eventData));
        manager.handleBotCommand(Provider.VK, userId, cmd).thenAccept(reply -> sendMessage(userId, reply));
    }

    private Optional<String> method(String method, Map<String, String> params) {
        try {
            StringBuilder form = new StringBuilder();
            for (Map.Entry<String, String> e : params.entrySet()) {
                form.append(enc(e.getKey())).append('=').append(enc(e.getValue())).append('&');
            }
            form.append("access_token=").append(enc(token)).append("&v=").append(API_VERSION);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(API + method))
                    .timeout(Duration.ofSeconds(15))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(form.toString(), StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() / 100 != 2) {
                logger.warning("VK: " + method + " вернул " + response.statusCode());
                return Optional.empty();
            }
            if (Json.parseObject(response.body()).containsKey("error")) {
                logger.warning("VK API rejected " + method);
                return Optional.empty();
            }
            return Optional.of(response.body());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        } catch (Exception e) {
            logger.warning("VK: " + method + " failed: " + e.getClass().getSimpleName());
            return Optional.empty();
        }
    }

    private void sleepQuietly() {
        try {
            Thread.sleep(5000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static String enc(String raw) {
        return URLEncoder.encode(raw == null ? "" : raw, StandardCharsets.UTF_8);
    }

    private static String str(Object value) {
        return value == null ? "" : value.toString();
    }
}
