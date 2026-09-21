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

package mc.t1rei.wauth.twofa.messenger;

import java.util.List;

public record BotReply(String text, List<Button> buttons, String promptToken) {
    public record Button(String label, String action) {}

    public static BotReply text(String text) { return new BotReply(text, List.of(), null); }

    public static BotReply menu(String text) {
        return new BotReply(text, List.of(new Button("Аккаунт", "status"),
                new Button("Сменить пароль", "password"), new Button("Заблокировать", "lock"),
                new Button("Разблокировать", "unlock"), new Button("Помощь", "help")), null);
    }

    public static BotReply confirm(String text, String token) {
        return new BotReply(text, List.of(new Button("Подтвердить", "confirm:" + token),
                new Button("Отмена", "cancel:" + token)), token);
    }

    public static BotReply login(String name, String ip, String token) {
        return new BotReply("Запрос входа: " + name + "\nIP: " + ip
                + "\nЕсли это не вы, отклоните вход и заблокируйте аккаунт в меню бота.",
                List.of(new Button("Это я", "approve:" + token), new Button("Отклонить", "deny:" + token)), token);
    }
}
