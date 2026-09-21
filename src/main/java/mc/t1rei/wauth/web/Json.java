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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class Json {

    private Json() {
    }

    public static Writer object() {
        return new Writer();
    }

    public static String escape(String raw) {
        StringBuilder sb = new StringBuilder(raw.length() + 8);
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }

    public record Raw(String json) {}

    static String value(Object v) {
        if (v == null) {
            return "null";
        }
        if (v instanceof Boolean || v instanceof Number) {
            return v.toString();
        }
        if (v instanceof Raw raw) {
            return raw.json();
        }
        if (v instanceof Writer w) {
            return w.build();
        }
        if (v instanceof Iterable<?> it) {
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (Object e : it) {
                if (!first) {
                    sb.append(',');
                }
                sb.append(value(e));
                first = false;
            }
            return sb.append(']').toString();
        }
        return "\"" + escape(v.toString()) + "\"";
    }

    public static final class Writer {
        private final StringBuilder sb = new StringBuilder("{");
        private boolean first = true;

        public Writer put(String key, Object v) {
            if (!first) {
                sb.append(',');
            }
            sb.append('"').append(escape(key)).append("\":").append(value(v));
            first = false;
            return this;
        }

        public String build() {
            return sb + "}";
        }

        @Override
        public String toString() {
            return build();
        }
    }

    public static Map<String, Object> parseObject(String text) {
        Parser p = new Parser(text);
        p.skipWs();
        Object v = p.value();
        p.skipWs();
        if (p.pos < p.src.length()) {
            throw new IllegalArgumentException("лишние символы после JSON");
        }
        if (!(v instanceof Map)) {
            throw new IllegalArgumentException("ожидался объект");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> map = (Map<String, Object>) v;
        return map;
    }

    private static final class Parser {
        private final String src;
        private int pos;
        private int depth;

        private Parser(String src) {
            this.src = src;
        }

        private void skipWs() {
            while (pos < src.length() && Character.isWhitespace(src.charAt(pos))) {
                pos++;
            }
        }

        private Object value() {
            if (++depth > 32) {
                throw new IllegalArgumentException("JSON nesting limit exceeded");
            }
            try {
            skipWs();
            if (pos >= src.length()) {
                throw new IllegalArgumentException("неожиданный конец JSON");
            }
            char c = src.charAt(pos);
            return switch (c) {
                case '{' -> object();
                case '[' -> array();
                case '"' -> string();
                case 't', 'f' -> literalBool();
                case 'n' -> literalNull();
                default -> number();
            };
            } finally {
                depth--;
            }
        }

        private Map<String, Object> object() {
            Map<String, Object> map = new LinkedHashMap<>();
            pos++;
            skipWs();
            if (peek() == '}') {
                pos++;
                return map;
            }
            while (true) {
                skipWs();
                String key = string();
                skipWs();
                expect(':');
                if (map.containsKey(key)) {
                    throw new IllegalArgumentException("duplicate JSON key");
                }
                map.put(key, value());
                skipWs();
                char c = next();
                if (c == '}') {
                    return map;
                }
                if (c != ',') {
                    throw new IllegalArgumentException("ожидалась ',' или '}'");
                }
            }
        }

        private List<Object> array() {
            List<Object> list = new ArrayList<>();
            pos++;
            skipWs();
            if (peek() == ']') {
                pos++;
                return list;
            }
            while (true) {
                list.add(value());
                skipWs();
                char c = next();
                if (c == ']') {
                    return list;
                }
                if (c != ',') {
                    throw new IllegalArgumentException("ожидалась ',' или ']'");
                }
            }
        }

        private String string() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (pos >= src.length()) {
                    throw new IllegalArgumentException("незакрытая строка");
                }
                char c = src.charAt(pos++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\') {
                    if (pos >= src.length()) {
                        throw new IllegalArgumentException("incomplete escape");
                    }
                    char e = src.charAt(pos++);
                    switch (e) {
                        case '"' -> sb.append('"');
                        case '\\' -> sb.append('\\');
                        case '/' -> sb.append('/');
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'u' -> {
                            if (pos + 4 > src.length()) {
                                throw new IllegalArgumentException("incomplete unicode escape");
                            }
                            sb.append((char) Integer.parseInt(src.substring(pos, pos + 4), 16));
                            pos += 4;
                        }
                        default -> throw new IllegalArgumentException("неверный escape \\" + e);
                    }
                } else {
                    if (c < 0x20) {
                        throw new IllegalArgumentException("unescaped control character");
                    }
                    sb.append(c);
                }
            }
        }

        private Object number() {
            int start = pos;
            while (pos < src.length() && "+-0123456789.eE".indexOf(src.charAt(pos)) >= 0) {
                pos++;
            }
            String num = src.substring(start, pos);
            if (num.isEmpty()) {
                throw new IllegalArgumentException("ожидалось значение");
            }
            if (num.indexOf('.') >= 0 || num.indexOf('e') >= 0 || num.indexOf('E') >= 0) {
                return Double.parseDouble(num);
            }
            return Long.parseLong(num);
        }

        private Boolean literalBool() {
            if (src.startsWith("true", pos)) {
                pos += 4;
                return Boolean.TRUE;
            }
            if (src.startsWith("false", pos)) {
                pos += 5;
                return Boolean.FALSE;
            }
            throw new IllegalArgumentException("неверный литерал");
        }

        private Object literalNull() {
            if (src.startsWith("null", pos)) {
                pos += 4;
                return null;
            }
            throw new IllegalArgumentException("неверный литерал");
        }

        private char peek() {
            skipWs();
            return pos < src.length() ? src.charAt(pos) : '\0';
        }

        private char next() {
            return pos < src.length() ? src.charAt(pos++) : '\0';
        }

        private void expect(char c) {
            skipWs();
            if (pos >= src.length() || src.charAt(pos) != c) {
                throw new IllegalArgumentException("ожидался '" + c + "'");
            }
            pos++;
        }
    }
}

