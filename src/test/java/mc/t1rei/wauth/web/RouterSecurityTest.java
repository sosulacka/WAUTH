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

import mc.t1rei.wauth.PlayerStore;
import mc.t1rei.wauth.twofa.TwoFactorManager;
import mc.t1rei.wauth.twofa.TwoFactorStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.UUID;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

class RouterSecurityTest {
    @TempDir Path dir;

    private TwoFactorManager manager() {
        Logger log = Logger.getLogger("RouterSecurityTest");
        return new TwoFactorManager(log, new TwoFactorStore(dir,
                new PlayerStore(dir, null, log), log, false, null), 600_000, 120_000, 1);
    }

    @Test void setupEndpointsRequireValidSessionToken() {
        TwoFactorManager manager = manager();
        String token = manager.createSetup(UUID.randomUUID(), "TestPlayer").sessionToken();
        Router router = new Router(manager);
        assertEquals(200, router.route("GET", "/api/setup/info", null, "Bearer " + token, null).status());
        assertEquals(200, router.route("GET", "/api/setup/info", "token=" + token, null, null).status());
        assertEquals(404, router.route("GET", "/api/setup/info", null, "Bearer wrong-token", null).status());
        assertEquals(404, router.route("GET", "/api/setup/status", null, "Bearer wrong-token", null).status());
    }

    @Test void rejectsWrongMethodsOnSetupEndpoints() {
        Router router = new Router(manager());
        assertEquals(405, router.route("POST", "/api/setup/info", null, null, null).status());
        assertEquals(405, router.route("DELETE", "/api/setup/status", null, null, null).status());
    }

    @Test void restrictsBodyAndStaticResources() {
        Router router = new Router(manager());
        assertEquals(413, router.route("POST", "/api/setup/info", null, null, new byte[Router.MAX_BODY + 1]).status());
        for (String path : new String[]{"/../config.yml", "/..\\config.yml", "/config.yml", "/unknown"}) {
            assertEquals(404, router.route("GET", path, null, null, null).status());
        }
        assertEquals(200, router.route("GET", "/setup", null, null, null).status());
        assertEquals(400, router.route("GET", "/api/setup/info", "token=%zz", null, null).status());
    }
}
