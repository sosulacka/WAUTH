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

package mc.t1rei.wauth.twofa;

import org.junit.jupiter.api.Test;

import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BackupCodesTest {

    private static final Pattern FORMAT = Pattern.compile("[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{4}-[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{4}");

    @Test
    void generatesCodesInExpectedFormat() {
        for (int i = 0; i < 200; i++) {
            String code = BackupCodes.generate();
            assertTrue(FORMAT.matcher(code).matches(), "неожиданный формат: " + code);
        }
    }

    @Test
    void alphabetExcludesConfusingCharacters() {
        for (int i = 0; i < 200; i++) {
            String code = BackupCodes.generate();
            assertFalse(code.matches(".*[01OIL].*"), "код содержит спорный символ: " + code);
        }
    }

    @Test
    void normalizeUppercasesAndStripsNoise() {
        assertEquals("ABCD2345", BackupCodes.normalize("abcd-2345"));
        assertEquals("ABCD2345", BackupCodes.normalize("  a b c d 2 3 4 5 "));
        assertEquals("ABCD", BackupCodes.normalize("A0B1C-OD-IL"));
        assertEquals("", BackupCodes.normalize(null));
    }

    @Test
    void generatedCodeSurvivesNormalization() {
        for (int i = 0; i < 50; i++) {
            String code = BackupCodes.generate();
            assertEquals(code.replace("-", ""), BackupCodes.normalize(code));
        }
    }
}
