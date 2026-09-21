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
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Logger;

public final class TelegramBot implements MessengerBot {

    private static final String API = "https://api.telegram.org/bot";
    private static final Duration POLL_TIMEOUT = Duration.ofSeconds(30);

    private final Logger logger;
    private final TwoFactorManager manager;
    private final String token;
    private final HttpClient http;

    private volatile boolean running;
    private Thread worker;
    private long offset;

    public TelegramBot(Logger logger, TwoFactorManager manager, String token) {
        this(logger, manager, token, HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());
    }

    TelegramBot(Logger logger, TwoFactorManager manager, String token, HttpClient http) {
        this.logger = logger;
        this.manager = manager;
        this.token = token;
        this.http = http;
    }

    @Override
    public void start() {
        if (token == null || token.isBlank()) {
            logger.warning("Telegram: токен не задан — бот не запущен.");
            return;
        }
        running = true;
        worker = new Thread(this::loop, "wauth-telegram");
        worker.setDaemon(true);
        worker.start();
        logger.info("Telegram-бот 2FA запущен.");
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

    private void loop() {
        while (running) {
            try {
                String body = Json.object()
                        .put("timeout", 25)
                        .put("offset", offset)
                        .build();
                Optional<String> response = api("getUpdates", body);
                if (response.isEmpty()) {
                    Thread.sleep(3000);
                    continue;
                }
                handleUpdates(response.get());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                logger.warning("Telegram polling failed: " + e.getClass().getSimpleName());
                sleepQuietly();
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void handleUpdates(String json) {
        Map<String, Object> root = Json.parseObject(json);
        if (!Boolean.TRUE.equals(root.get("ok")) || !(root.get("result") instanceof List<?> updates)) {
            return;
        }
        for (Object u : updates) {
            if (!(u instanceof Map)) {
                continue;
            }
            Map<String, Object> update = (Map<String, Object>) u;
            long updateId = asLong(update.get("update_id"));
            offset = Math.max(offset, updateId + 1);
            if (update.get("callback_query") instanceof Map) {
                handleCallback((Map<String, Object>) update.get("callback_query"));
            } else if (update.get("message") instanceof Map) {
                handleMessage((Map<String, Object>) update.get("message"));
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void handleMessage(Map<String, Object> message) {
        Object from = message.get("from");
        Object chat = message.get("chat");
        String text = message.get("text") == null ? "" : message.get("text").toString();
        if (!(chat instanceof Map)) {
            return;
        }
        String chatId = str(((Map<String, Object>) chat).get("id"));
        String userId = from instanceof Map ? str(((Map<String, Object>) from).get("id")) : "";
        if (!"private".equals(str(((Map<String, Object>) chat).get("type"))) || !userId.equals(chatId)
                || !(from instanceof Map<?, ?> sender) || Boolean.TRUE.equals(sender.get("is_bot"))) {
            return;
        }

        String code = text.trim();
        if (code.isEmpty()) {
            return;
        }
        if (code.matches("(?is)^/?(password|changepass)\\b.*")) {
            String messageId = str(message.get("message_id"));
            if (!messageId.isBlank() && !delete(chatId, messageId))
                sendMessage(chatId, BotReply.text("Не удалось удалить сообщение с паролем. Удалите его вручную."));
        }
        manager.handleBotCommand(Provider.TELEGRAM, userId, code).thenAccept(result -> sendMessage(chatId, result));
    }

    @SuppressWarnings("unchecked")
    private void handleCallback(Map<String, Object> callback) {
        String id = str(callback.get("id"));
        String data = str(callback.get("data"));
        String userId = callback.get("from") instanceof Map<?, ?> from ? str(from.get("id")) : "";
        if (!(callback.get("message") instanceof Map<?, ?> message) || !(message.get("chat") instanceof Map<?, ?> chat)
                || !"private".equals(str(chat.get("type"))) || !userId.equals(str(chat.get("id")))) return;
        answerCallback(id, "Обрабатываю запрос...");
        manager.handleBotCommand(Provider.TELEGRAM, userId, data).thenAccept(result -> sendMessage(userId, result));
    }

    @Override
    public void sendMessage(String chatId, BotReply reply) {
        Json.Writer body = Json.object().put("chat_id", chatId).put("text", reply.text()).put("protect_content", true);
        if (!reply.buttons().isEmpty()) {
            var rows = reply.buttons().stream().map(button -> List.of(Json.object().put("text", button.label())
                    .put("callback_data", button.action()))).toList();
            body.put("reply_markup", raw(Json.object().put("inline_keyboard", rows).build()));
        }
        String response = api("sendMessage", body.build()).orElseThrow(() -> new IllegalStateException("Telegram delivery failed"));
        if (reply.promptToken() != null) {
            Object result = Json.parseObject(response).get("result");
            if (result instanceof Map<?, ?> message) {
                String messageId = str(message.get("message_id"));
                manager.trackPrompt(reply.promptToken(), () -> {
                    if (!delete(chatId, messageId)) api("editMessageText", Json.object().put("chat_id", chatId)
                            .put("message_id", messageId).put("text", "Запрос закрыт.")
                            .put("reply_markup", Json.object().put("inline_keyboard", List.of())).build());
                });
            }
        }
    }

    private boolean delete(String chat, String message) {
        return api("deleteMessage", Json.object().put("chat_id", chat).put("message_id", message).build()).isPresent();
    }

    private void answerCallback(String id, String text) {
        api("answerCallbackQuery", Json.object().put("callback_query_id", id).put("text", text).build());
    }

    private Optional<String> api(String method, String jsonBody) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(API + token + "/" + method))
                    .timeout(method.equals("getUpdates") ? POLL_TIMEOUT.plusSeconds(5) : Duration.ofSeconds(10))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() / 100 != 2) {
                logger.warning("Telegram: " + method + " вернул " + response.statusCode());
                return Optional.empty();
            }
            if (!Boolean.TRUE.equals(Json.parseObject(response.body()).get("ok"))) return Optional.empty();
            return Optional.of(response.body());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        } catch (Exception e) {
            logger.warning("Telegram: " + method + " failed: " + e.getClass().getSimpleName());
            return Optional.empty();
        }
    }

    private static Object raw(String json) {
        return new Json.Raw(json);
    }

    private void sleepQuietly() {
        try {
            Thread.sleep(3000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static long asLong(Object value) {
        return value instanceof Number n ? n.longValue() : Long.parseLong(str(value));
    }

    private static String str(Object value) {
        return value == null ? "" : value.toString();
    }

}
