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

import java.security.SecureRandom;
import java.util.Locale;

public final class BackupCodes {

    private static final char[] ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789".toCharArray();
    private static final int GROUP = 4;
    private static final SecureRandom RANDOM = new SecureRandom();

    private BackupCodes() {
    }

    public static String generate() {
        StringBuilder sb = new StringBuilder(GROUP * 2 + 1);
        for (int i = 0; i < GROUP * 2; i++) {
            if (i == GROUP) {
                sb.append('-');
            }
            sb.append(ALPHABET[RANDOM.nextInt(ALPHABET.length)]);
        }
        return sb.toString();
    }

    public static String normalize(String raw) {
        if (raw == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (char c : raw.toUpperCase(Locale.ROOT).toCharArray()) {
            if (contains(c)) {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static boolean contains(char c) {
        for (char a : ALPHABET) {
            if (a == c) {
                return true;
            }
        }
        return false;
    }
}
