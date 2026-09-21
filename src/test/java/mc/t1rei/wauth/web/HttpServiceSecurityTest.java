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

import org.junit.jupiter.api.Test;

import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

class HttpServiceSecurityTest {
    @Test void realTransportSetsHeadersAndRejectsOversizedBodiesBeforeReadingThem() throws Exception {
        HttpService service = new HttpService(Logger.getLogger("HttpServiceSecurityTest"),
                new Router(null), "127.0.0.1", 0);
        service.start();
        try (HttpClient client = HttpClient.newHttpClient()) {
            URI base = URI.create("http://127.0.0.1:" + service.localPort());
            var page = client.send(HttpRequest.newBuilder(base.resolve("/setup"))
                    .timeout(Duration.ofSeconds(5)).GET().build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, page.statusCode());
            Router.SECURITY_HEADERS.forEach((name, value) -> assertEquals(value, page.headers().firstValue(name).orElseThrow()));
            var unknown = client.send(HttpRequest.newBuilder(base.resolve("/api/does-not-exist"))
                    .timeout(Duration.ofSeconds(5)).GET().build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(404, unknown.statusCode());
            try (Socket socket = new Socket("127.0.0.1", service.localPort())) {
                socket.setSoTimeout(5000);
                socket.getOutputStream().write(("POST /api/setup/status HTTP/1.1\r\nHost: localhost\r\n"
                        + "Content-Length: 99999999\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                String status = new java.io.BufferedReader(new java.io.InputStreamReader(socket.getInputStream())).readLine();
                assertTrue(status.contains("413"), status);
            }
        } finally {
            service.stop();
        }
    }
}
