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
import net.kyori.adventure.text.TextComponent;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.format.TextColor;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TextTest {

    @Test
    void expandsCompactHexIntoRepeatedFormat() {
        assertEquals("&x&F&0&F&F&A&BE", Text.expandHex("&#F0FFABE"));
        assertEquals("plain &a text", Text.expandHex("plain &a text"));
    }

    @Test
    void bothHexFormatsProduceIdenticalComponents() {
        Component compact = Text.color("&#F0FFABE&#F3EC9Ex");
        Component repeated = Text.color("&x&F&0&F&F&A&BE&x&F&3&E&C&9&Ex");
        assertEquals(repeated, compact);
    }

    @Test
    void appliesHexColorToFollowingText() {
        Component component = Text.color("&#FF8C5EWAUTH");
        TextComponent first = firstPart(component);
        assertEquals(TextColor.fromHexString("#FF8C5E"), first.color());
        assertEquals("WAUTH", first.content());
    }

    @Test
    void supportsLegacyColorCodes() {
        assertEquals(NamedTextColor.GREEN, firstPart(Text.color("&aok")).color());
    }

    @Test
    void stripsEveryColorFormat() {
        assertEquals("WAUTH", Text.strip("&x&F&0&F&F&A&BW&#FF8C5EA&aU&cT&rH"));
    }

    private TextComponent firstPart(Component component) {
        return component.children().isEmpty()
                ? (TextComponent) component
                : (TextComponent) component.children().get(0);
    }

    @Test
    void parsesDurationsInSecondsAndMilliseconds() {
        assertEquals(500L, Text.parseDuration("500ms", -1L));
        assertEquals(45_000L, Text.parseDuration("45s", -1L));
        assertEquals(45_000L, Text.parseDuration("45", -1L));
        assertEquals(120_000L, Text.parseDuration("2m", -1L));
        assertEquals(1_500L, Text.parseDuration("1.5s", -1L));
        assertEquals(3_600_000L, Text.parseDuration("1h", -1L));
        assertEquals(50L, Text.parseDuration("1t", -1L));
    }

    @Test
    void fallsBackOnInvalidDuration() {
        assertEquals(777L, Text.parseDuration("abc", 777L));
        assertEquals(777L, Text.parseDuration(null, 777L));
        assertEquals(30_000L, Text.parseDuration(30, -1L));
    }

    @Test
    void formatsDurationsForMessages() {
        assertEquals("900 мс", Text.formatDuration(900L));
        assertEquals("45 сек", Text.formatDuration(45_000L));
        assertEquals("2 мин", Text.formatDuration(120_000L));
    }

    @Test
    void trimsCoordinatesToTwoDecimals() {
        assertEquals("12.35", Text.trimCoordinate(12.3456D));
        assertEquals("-0.50", Text.trimCoordinate(-0.5D));
    }
}
