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

package mc.t1rei.wauth.core;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.TextDecoration;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;

import java.util.Arrays;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class Text {

    private static final Pattern HEX_COMPACT = Pattern.compile("&#([0-9A-Fa-f]{6})");

    private static final Pattern ANY_CODE = Pattern.compile(
            "(?i)&x(?:&[0-9A-F]){6}|&#[0-9A-F]{6}|&[0-9A-FK-OR]|§x(?:§[0-9A-F]){6}|§[0-9A-FK-OR]");

    private static final Pattern DURATION = Pattern.compile(
            "^\\s*(\\d+(?:[.,]\\d+)?)\\s*(ms|millis?|milliseconds?|t|ticks?|s|sec|secs|seconds?|m|min|mins|minutes?|h|hours?|d|days?)?\\s*$",
            Pattern.CASE_INSENSITIVE);

    private static final LegacyComponentSerializer LEGACY = LegacyComponentSerializer.builder()
            .character('&')
            .hexCharacter('#')
            .hexColors()
            .useUnusualXRepeatedCharacterHexFormat()
            .build();

    private Text() {
    }

    public static Component color(String raw) {
        if (raw == null || raw.isEmpty()) {
            return Component.empty();
        }
        return LEGACY.deserialize(expandHex(raw)).decoration(TextDecoration.ITALIC, false);
    }

    public static String plain(Component component) {
        return PlainTextComponentSerializer.plainText().serialize(component);
    }

    public static String strip(String raw) {
        return raw == null ? "" : ANY_CODE.matcher(raw).replaceAll("");
    }
    public static String expandHex(String raw) {
        Matcher matcher = HEX_COMPACT.matcher(raw);
        if (!matcher.find()) {
            return raw;
        }
        matcher.reset();
        StringBuilder out = new StringBuilder(raw.length() + 32);
        while (matcher.find()) {
            StringBuilder replacement = new StringBuilder("&x");
            for (char digit : matcher.group(1).toCharArray()) {
                replacement.append('&').append(digit);
            }
            matcher.appendReplacement(out, Matcher.quoteReplacement(replacement.toString()));
        }
        matcher.appendTail(out);
        return out.toString();
    }

    public static long parseDuration(Object value, long fallbackMillis) {
        if (value == null) {
            return fallbackMillis;
        }
        if (value instanceof Number number) {
            return Math.round(number.doubleValue() * 1000.0D);
        }
        Matcher matcher = DURATION.matcher(value.toString());
        if (!matcher.matches()) {
            return fallbackMillis;
        }
        double amount = Double.parseDouble(matcher.group(1).replace(',', '.'));
        String unit = matcher.group(2) == null ? "s" : matcher.group(2).toLowerCase(Locale.ROOT);
        double factor = switch (unit) {
            case "ms", "milli", "millis", "millisecond", "milliseconds" -> 1.0D;
            case "t", "tick", "ticks" -> 50.0D;
            case "m", "min", "mins", "minute", "minutes" -> 60_000.0D;
            case "h", "hour", "hours" -> 3_600_000.0D;
            case "d", "day", "days" -> 86_400_000.0D;
            default -> 1000.0D;
        };
        return Math.max(0L, Math.round(amount * factor));
    }
    public static String formatDuration(long millis) {
        if (millis < 1000L) {
            return millis + " мс";
        }
        long totalSeconds = (millis + 999L) / 1000L;
        long hours = totalSeconds / 3600L;
        long minutes = (totalSeconds % 3600L) / 60L;
        long seconds = totalSeconds % 60L;
        StringBuilder sb = new StringBuilder();
        if (hours > 0L) {
            sb.append(hours).append(" ч ");
        }
        if (minutes > 0L) {
            sb.append(minutes).append(" мин ");
        }
        if (seconds > 0L || sb.isEmpty()) {
            sb.append(seconds).append(" сек");
        }
        return sb.toString().trim();
    }

    public static String trimCoordinate(double value) {
        return String.format(Locale.ROOT, "%.2f", value);
    }

    public static String replace(String input, String... placeholders) {
        String result = input;
        for (int i = 0; i + 1 < placeholders.length; i += 2) {
            result = result.replace(placeholders[i], placeholders[i + 1] == null ? "" : placeholders[i + 1]);
        }
        return result;
    }

    public static void wipe(char[] secret) {
        if (secret != null) {
            Arrays.fill(secret, '\0');
        }
    }
}
