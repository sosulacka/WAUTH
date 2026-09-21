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

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

public final class HttpService {

    private final Logger logger;
    private final Router router;
    private final String host;
    private final int port;

    private HttpServer server;
    private ThreadPoolExecutor executor;

    public HttpService(Logger logger, Router router, String host, int port) {
        this.logger = logger;
        this.router = router;
        this.host = host;
        this.port = port;
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(host, port), 64);
        executor = new ThreadPoolExecutor(2, 4, 30, TimeUnit.SECONDS, new ArrayBlockingQueue<>(64), r -> {
            Thread t = new Thread(r, "wauth-http");
            t.setDaemon(true);
            return t;
        });
        server.setExecutor(executor);
        server.createContext("/", this::handle);
        server.start();
        logger.info("2FA HTTP-сервис слушает " + host + ":" + port);
    }

    public void stop() {
        if (server != null) {
            server.stop(0);
            server = null;
        }
        if (executor != null) {
            executor.shutdownNow();
            executor = null;
        }
    }

    private void handle(HttpExchange ex) throws IOException {
        try (ex) {
            long declaredLength = -1L;
            String length = ex.getRequestHeaders().getFirst("Content-Length");
            if (length != null) {
                try {
                    declaredLength = Long.parseLong(length);
                } catch (NumberFormatException ignored) {
                    declaredLength = Router.MAX_BODY + 1L;
                }
            }
            byte[] body = declaredLength > Router.MAX_BODY
                    ? new byte[Router.MAX_BODY + 1]
                    : ex.getRequestBody().readNBytes(Router.MAX_BODY + 1);
            Router.Response response = router.route(
                    ex.getRequestMethod(), ex.getRequestURI().getPath(), ex.getRequestURI().getRawQuery(),
                    ex.getRequestHeaders().getFirst("Authorization"), body);
            ex.getResponseHeaders().set("Content-Type", response.contentType());
            Router.SECURITY_HEADERS.forEach((name, value) -> ex.getResponseHeaders().set(name, value));
            ex.getResponseHeaders().set("Connection", "close");
            ex.sendResponseHeaders(response.status(), response.body().length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(response.body());
            }
        }
    }

    int localPort() {
        return server.getAddress().getPort();
    }
}

