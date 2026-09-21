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

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Marker;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.filter.AbstractFilter;
import org.apache.logging.log4j.message.Message;

import java.util.Locale;
import java.util.Set;

public final class ConsoleFilter extends AbstractFilter {

    private static final String MARKER = "command: /";

    private final Set<String> secretCommands;
    private volatile boolean active = true;

    private ConsoleFilter(Set<String> secretCommands) {
        this.secretCommands = secretCommands;
    }

    public static ConsoleFilter install(Set<String> secretCommands, java.util.logging.Logger fallbackLogger) {
        ConsoleFilter filter = new ConsoleFilter(secretCommands);
        try {
            ((Logger) LogManager.getRootLogger()).addFilter(filter);
            return filter;
        } catch (Throwable throwable) {
            fallbackLogger.warning("Не удалось установить фильтр консоли: пароли могут попасть в лог ("
                    + throwable.getClass().getSimpleName() + ").");
            return null;
        }
    }

    public void uninstall() {
        active = false;
    }

    private Result evaluate(String message) {
        if (!active || message == null) {
            return Result.NEUTRAL;
        }
        String lower = message.toLowerCase(Locale.ROOT);
        int index = lower.indexOf(MARKER);
        if (index < 0) {
            return Result.NEUTRAL;
        }
        String tail = lower.substring(index + MARKER.length());
        int end = 0;
        while (end < tail.length() && !Character.isWhitespace(tail.charAt(end))) {
            end++;
        }
        String label = tail.substring(0, end);
        int colon = label.indexOf(':');
        if (colon >= 0) {
            label = label.substring(colon + 1);
        }
        return secretCommands.contains(label) ? Result.DENY : Result.NEUTRAL;
    }

    @Override
    public Result filter(LogEvent event) {
        Message message = event == null ? null : event.getMessage();
        return message == null ? Result.NEUTRAL : evaluate(message.getFormattedMessage());
    }

    @Override
    public Result filter(Logger logger, Level level, Marker marker, Message message, Throwable throwable) {
        return message == null ? Result.NEUTRAL : evaluate(message.getFormattedMessage());
    }

    @Override
    public Result filter(Logger logger, Level level, Marker marker, String message, Object... params) {
        return evaluate(message);
    }

    @Override
    public Result filter(Logger logger, Level level, Marker marker, Object message, Throwable throwable) {
        return evaluate(message == null ? null : message.toString());
    }
}
