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

package mc.t1rei.wauth.storage;

import mc.t1rei.wauth.PlayerStore.Account;
import mc.t1rei.wauth.twofa.Provider;
import mc.t1rei.wauth.twofa.TwoFactorStore.Binding;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

public final class StorageCodec {
    private StorageCodec() {}

    public static List<Account> accounts(List<String> rows) {
        List<Account> accounts = new ArrayList<>();
        Set<UUID> ids = new HashSet<>();
        int line = 0;
        for (String row : rows) {
            line++;
            try {
                String[] p = row.split("\t", -1);
                if (p.length != 6 && p.length != 7) throw new IllegalArgumentException("Malformed account record");
                if (p.length == 7 && !p[6].equals("true") && !p[6].equals("false")) throw new IllegalArgumentException("Invalid lock flag");
                Account a = new Account(UUID.fromString(p[0]), p[1], p[2], Long.parseLong(p[3]), Long.parseLong(p[4]), p[5],
                        p.length == 7 && Boolean.parseBoolean(p[6]));
                if (a.name().isBlank()) throw new IllegalArgumentException("empty player name");
                if (a.hash().isBlank()) throw new IllegalArgumentException("empty password hash");
                if (!ids.add(a.uuid())) throw new IllegalArgumentException("duplicate UUID " + a.uuid());
                accounts.add(a);
            } catch (IllegalArgumentException failure) {
                throw new IllegalArgumentException("accounts.db record " + line + ": "
                        + (failure instanceof NumberFormatException ? "invalid UUID/timestamp" : safeAccountError(failure)));
            }
        }
        return accounts;
    }

    private static String safeAccountError(IllegalArgumentException failure) {
        String message = failure.getMessage();
        return message != null && (message.startsWith("duplicate UUID ") || message.startsWith("empty "))
                ? message : "invalid UUID or record format";
    }

    public static List<Binding> bindings(List<String> rows) {
        List<Binding> bindings = new ArrayList<>();
        Set<UUID> ids = new HashSet<>();
        Set<String> messengers = new HashSet<>();
        for (String row : rows) {
            String[] p = fields(row);
            if (!p[1].equals("true") && !p[1].equals("false")) throw new IllegalArgumentException("Invalid enabled flag");
            Provider provider = p[2].isBlank() ? null : Provider.parse(p[2]).orElseThrow();
            if ((provider == null) != p[3].isBlank()
                    || (provider != null && !p[3].matches("[1-9][0-9]{0,24}"))) {
                throw new IllegalArgumentException("Invalid messenger identity");
            }
            UUID uuid = UUID.fromString(p[0]);
            if (!ids.add(uuid) || (provider != null && !messengers.add(provider.name() + ":" + p[3]))) {
                throw new IllegalArgumentException("Duplicate 2FA binding");
            }
            List<String> hashes = p[4].isEmpty() ? List.of() : List.of(p[4].split(";"));
            bindings.add(new Binding(uuid, Boolean.parseBoolean(p[1]), provider, p[3].isBlank() ? null : p[3], hashes, Long.parseLong(p[5])));
        }
        return bindings;
    }

    public static String account(Account a) {
        return String.join("\t", a.uuid().toString(), field(a.name()), field(a.hash()), Long.toString(a.registeredAt()),
                Long.toString(a.lastLoginAt()), field(a.lastIp() == null ? "" : a.lastIp())) + (a.locked() ? "\ttrue" : "");
    }

    public static String binding(Binding b) {
        return String.join("\t", b.uuid().toString(), Boolean.toString(b.enabled()),
                b.provider() == null ? "" : b.provider().name(), field(b.messengerId() == null ? "" : b.messengerId()),
                field(String.join(";", b.backupHashes())), Long.toString(b.createdAt()));
    }

    private static String field(String value) {
        if (value.indexOf('\t') >= 0 || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) throw new IllegalArgumentException("Invalid storage field");
        return value;
    }

    private static String[] fields(String row) {
        String[] parts = row.split("\t", -1);
        if (parts.length != 6) throw new IllegalArgumentException("Malformed authentication record");
        return parts;
    }
}
