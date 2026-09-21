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

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonTest {

    @Test
    void writesPrimitivesAndEscapes() {
        String json = Json.object()
                .put("name", "a\"b\\c")
                .put("n", 42)
                .put("flag", true)
                .put("nil", null)
                .build();
        assertEquals("{\"name\":\"a\\\"b\\\\c\",\"n\":42,\"flag\":true,\"nil\":null}", json);
    }

    @Test
    void writesArraysAndRaw() {
        String json = Json.object()
                .put("codes", List.of("A", "B"))
                .put("nested", new Json.Raw("{\"x\":1}"))
                .build();
        assertEquals("{\"codes\":[\"A\",\"B\"],\"nested\":{\"x\":1}}", json);
    }

    @Test
    void parsesObject() {
        Map<String, Object> map = Json.parseObject("{\"token\":\"ff00\",\"approved\":true,\"n\":7}");
        assertEquals("ff00", map.get("token"));
        assertEquals(Boolean.TRUE, map.get("approved"));
        assertEquals(7L, map.get("n"));
    }

    @Test
    void parsesNestedAndArrays() {
        Map<String, Object> map = Json.parseObject(
                "{\"a\":{\"b\":\"c\"},\"list\":[1,2,3],\"esc\":\"line\\nbreak\"}");
        assertTrue(map.get("a") instanceof Map);
        assertEquals("c", ((Map<?, ?>) map.get("a")).get("b"));
        assertEquals(List.of(1L, 2L, 3L), map.get("list"));
        assertEquals("line\nbreak", map.get("esc"));
    }

    @Test
    void roundTripsThroughWriterAndParser() {
        String json = Json.object().put("provider", "TELEGRAM").put("messengerId", "42").build();
        Map<String, Object> map = Json.parseObject(json);
        assertEquals("TELEGRAM", map.get("provider"));
        assertEquals("42", map.get("messengerId"));
    }

    @Test
    void rejectsMalformedJson() {
        assertThrows(IllegalArgumentException.class, () -> Json.parseObject("{"));
        assertThrows(IllegalArgumentException.class, () -> Json.parseObject("{\"a\":}"));
        assertThrows(IllegalArgumentException.class, () -> Json.parseObject("[1,2]"));
        assertThrows(IllegalArgumentException.class, () -> Json.parseObject("{\"a\":1}trailing"));
        assertThrows(IllegalArgumentException.class, () -> Json.parseObject("{\"a\":null,\"a\":true}"));
        assertThrows(IllegalArgumentException.class, () -> Json.parseObject("{\"a\":\"line\nbreak\"}"));
        assertThrows(IllegalArgumentException.class, () -> Json.parseObject("{\"a\":" + "[".repeat(5000) + "0" + "]".repeat(5000) + "}"));
    }

    @Test
    void unicodeStaysIntact() {
        String json = Json.object().put("player", "Игрок🔐").build();
        assertFalse(json.isEmpty());
        assertEquals("Игрок🔐", Json.parseObject(json).get("player"));
    }
}
