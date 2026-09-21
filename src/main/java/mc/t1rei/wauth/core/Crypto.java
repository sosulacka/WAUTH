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

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Logger;

public final class Crypto {

    private static final int GCM_TAG_BITS = 128;
    private static final int IV_LENGTH = 12;
    private static final int KEY_LENGTH = 32;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final SecretKey key;

    private Crypto(SecretKey key) {
        this.key = key;
    }

    public static Crypto load(Path keyFile, Logger logger) throws IOException {
        if (Files.exists(keyFile)) {
            byte[] decoded = Base64.getDecoder().decode(Files.readString(keyFile, StandardCharsets.UTF_8).trim());
            if (decoded.length == KEY_LENGTH) {
                return new Crypto(new SecretKeySpec(decoded, "AES"));
            }
            throw new IOException("Invalid storage key length; restore the original key from backup");
        }
        byte[] material = new byte[KEY_LENGTH];
        RANDOM.nextBytes(material);
        Files.createDirectories(keyFile.getParent());
        Files.writeString(keyFile, Base64.getEncoder().encodeToString(material), StandardCharsets.UTF_8);
        return new Crypto(new SecretKeySpec(material, "AES"));
    }

    public String encrypt(String plain) throws Exception {
        byte[] iv = new byte[IV_LENGTH];
        RANDOM.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] encrypted = cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8));
        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
        return Base64.getEncoder().encodeToString(combined);
    }

    public String decrypt(String encoded) throws Exception {
        byte[] combined = Base64.getDecoder().decode(encoded.trim());
        byte[] iv = Arrays.copyOfRange(combined, 0, IV_LENGTH);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] plain = cipher.doFinal(combined, IV_LENGTH, combined.length - IV_LENGTH);
        return new String(plain, StandardCharsets.UTF_8);
    }
}
