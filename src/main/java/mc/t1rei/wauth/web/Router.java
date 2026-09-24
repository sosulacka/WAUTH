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

package mc.t1rei.wauth.web;

import mc.t1rei.wauth.twofa.TwoFactorManager;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Map;

public final class Router {

    public record Response(int status, String contentType, byte[] body) {
        static Response json(int status, String json) {
            return new Response(status, "application/json; charset=utf-8", json.getBytes(StandardCharsets.UTF_8));
        }
    }

    public static final int MAX_BODY = 64 * 1024;

    public static final Map<String, String> SECURITY_HEADERS = Map.of(
            "Cache-Control", "no-store",
            "Referrer-Policy", "no-referrer",
            "X-Content-Type-Options", "nosniff",
            "X-Frame-Options", "DENY",
            "Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; "
                    + "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
                    + "base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            "Permissions-Policy", "camera=(), microphone=(), geolocation=()");

    private final TwoFactorManager manager;
    private final String telegramUsername;

    public Router(TwoFactorManager manager) { this(manager, ""); }
    public Router(TwoFactorManager manager, String telegramUsername) {
        this.manager = manager;
        String username = telegramUsername == null ? "" : telegramUsername.trim().replaceFirst("^@", "");
        this.telegramUsername = username.matches("[A-Za-z][A-Za-z0-9_]{4,31}") ? username : "";
    }

    public Response route(String method, String path, String rawQuery, String authHeader, byte[] body) {
        try {
            if (body != null && body.length > MAX_BODY) {
                return Response.json(413, error("request too large"));
            }
            if (path == null || path.length() > 2048 || (rawQuery != null && rawQuery.length() > 2048)) {
                return Response.json(414, error("URI too long"));
            }
            return switch (path) {
                case "/api/setup/info" -> get(method, () -> setupInfo(setupToken(authHeader, rawQuery)));
                case "/api/setup/status" -> get(method, () -> setupStatus(setupToken(authHeader, rawQuery)));
                default -> serveStatic(method, path);
            };
        } catch (IllegalArgumentException exception) {
            return Response.json(400, error("invalid request"));
        } catch (RuntimeException exception) {
            return Response.json(500, error("internal error"));
        }
    }

    private Response setupInfo(String token) {
        Optional<TwoFactorManager.SetupInfo> info = manager.setupInfo(token);
        if (info.isEmpty()) {
            return Response.json(404, error("unknown or expired session"));
        }
        TwoFactorManager.SetupInfo i = info.get();
        return Response.json(200, Json.object()
                .put("playerName", i.playerName())
                .put("code", i.code())
                .put("expiresAt", i.expiresAt())
                .build());
    }

    private Response setupStatus(String token) {
        Optional<TwoFactorManager.SetupStatus> status = manager.setupStatus(token);
        if (status.isEmpty()) {
            return Response.json(404, error("unknown or expired session"));
        }
        TwoFactorManager.SetupStatus s = status.get();
        Json.Writer out = Json.object()
                .put("linked", s.linked())
                .put("needsConfirm", s.needsConfirm())
                .put("provider", s.provider() == null ? null : s.provider().name());
        if (s.backup() != null) {
            out.put("backup", s.backup());
        }
        return Response.json(200, out.build());
    }

    private Response serveStatic(String method, String path) {
        if (!method.equalsIgnoreCase("GET")) {
            return Response.json(405, error("method not allowed"));
        }
        String clean = path;
        if (clean.equals("/") || clean.equals("/setup")) {
            clean = "/index.html";
        }
        if (!List.of("/index.html", "/styles.css", "/app.js").contains(clean)) {
            return Response.json(404, error("not found"));
        }
        String resource = "web" + clean;
        try (InputStream in = Router.class.getClassLoader().getResourceAsStream(resource)) {
            if (in == null) {
                return Response.json(404, error("not found"));
            }
            byte[] bytes = in.readAllBytes();
            if (clean.equals("/index.html")) {
                String html = new String(bytes, StandardCharsets.UTF_8);
                if (telegramUsername.isEmpty()) {
                    html = html.replace("id=\"open-bot\" href=\"#\"", "id=\"open-bot\" aria-disabled=\"true\" tabindex=\"-1\"");
                } else {
                    html = html.replace("id=\"open-bot\" href=\"#\"", "id=\"open-bot\" href=\"https://t.me/" + telegramUsername + "\"")
                            .replace("Бот не настроен", "@" + telegramUsername);
                }
                bytes = html.getBytes(StandardCharsets.UTF_8);
            }
            return new Response(200, contentType(clean), bytes);
        } catch (Exception exception) {
            return Response.json(500, error("read error"));
        }
    }

    private Response get(String method, java.util.function.Supplier<Response> action) {
        if (!method.equalsIgnoreCase("GET")) {
            return Response.json(405, error("method not allowed"));
        }
        return action.get();
    }

    private static String setupToken(String header, String rawQuery) {
        return header != null && header.startsWith("Bearer ") ? header.substring(7) : query(rawQuery, "token");
    }

    private static String query(String rawQuery, String key) {
        if (rawQuery == null) {
            return "";
        }
        for (String pair : rawQuery.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0 && pair.substring(0, eq).equals(key)) {
                return java.net.URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            }
        }
        return "";
    }

    private static String error(String message) {
        return Json.object().put("error", message).build();
    }

    private static String contentType(String path) {
        String lower = path.toLowerCase(Locale.ROOT);
        if (lower.endsWith(".html")) return "text/html; charset=utf-8";
        if (lower.endsWith(".css")) return "text/css; charset=utf-8";
        if (lower.endsWith(".js")) return "application/javascript; charset=utf-8";
        if (lower.endsWith(".svg")) return "image/svg+xml";
        if (lower.endsWith(".woff2")) return "font/woff2";
        if (lower.endsWith(".png")) return "image/png";
        return "application/octet-stream";
    }
}
