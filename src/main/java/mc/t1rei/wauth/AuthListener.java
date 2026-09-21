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

package mc.t1rei.wauth;

import com.destroystokyo.paper.event.player.PlayerJumpEvent;
import io.papermc.paper.event.player.AsyncChatEvent;
import org.bukkit.Location;
import org.bukkit.entity.Entity;
import org.bukkit.entity.Player;
import org.bukkit.entity.Projectile;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.entity.EntityDamageByEntityEvent;
import org.bukkit.event.entity.EntityDamageEvent;
import org.bukkit.event.entity.EntityPickupItemEvent;
import org.bukkit.event.entity.EntityTargetEvent;
import org.bukkit.event.entity.FoodLevelChangeEvent;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.inventory.InventoryDragEvent;
import org.bukkit.event.inventory.InventoryOpenEvent;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.player.PlayerDropItemEvent;
import org.bukkit.event.player.PlayerInteractEntityEvent;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.event.player.PlayerItemConsumeEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerMoveEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.event.player.PlayerSwapHandItemsEvent;
import org.bukkit.event.player.PlayerToggleFlightEvent;
import org.bukkit.event.player.PlayerToggleSprintEvent;
import org.bukkit.event.player.PlayerVelocityEvent;

import java.util.Locale;

public final class AuthListener implements Listener {

    private static final double EPSILON = 1.0E-4D;

    private final AuthConfig config;
    private final AuthManager auth;

    public AuthListener(AuthConfig config, AuthManager auth) {
        this.config = config;
        this.auth = auth;
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onPreLogin(org.bukkit.event.player.AsyncPlayerPreLoginEvent event) {
        if (auth.loginBlocked(event.getUniqueId())) {
            event.disallow(org.bukkit.event.player.AsyncPlayerPreLoginEvent.Result.KICK_BANNED,
                    config.message("account-locked"));
        }
    }

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onJoin(PlayerJoinEvent event) {
        auth.begin(event.getPlayer());
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onQuit(PlayerQuitEvent event) {
        auth.refreshSession(event.getPlayer());
        auth.abandon(event.getPlayer());
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onMove(PlayerMoveEvent event) {
        Location frozen = auth.frozenLocation(event.getPlayer());
        if (frozen == null) {
            return;
        }
        Location to = event.getTo();
        boolean moved = config.blockMovement() && !samePosition(to, frozen);
        boolean looked = config.blockCamera()
                && (Float.compare(to.getYaw(), frozen.getYaw()) != 0 || Float.compare(to.getPitch(), frozen.getPitch()) != 0);
        if (!moved && !looked) {
            return;
        }
        Location target = frozen.clone();
        if (!config.blockCamera()) {
            target.setYaw(to.getYaw());
            target.setPitch(to.getPitch());
        }
        if (!config.blockMovement()) {
            target.setX(to.getX());
            target.setY(to.getY());
            target.setZ(to.getZ());
        }
        event.setTo(target);
    }

    private boolean samePosition(Location a, Location b) {
        return a.getWorld() == b.getWorld()
                && Math.abs(a.getX() - b.getX()) < EPSILON
                && Math.abs(a.getY() - b.getY()) < EPSILON
                && Math.abs(a.getZ() - b.getZ()) < EPSILON;
    }

    @EventHandler(ignoreCancelled = true)
    public void onJump(PlayerJumpEvent event) {
        if (config.blockJump() && auth.isPending(event.getPlayer())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(ignoreCancelled = true)
    public void onSprint(PlayerToggleSprintEvent event) {
        if (config.blockSprint() && auth.isPending(event.getPlayer())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(ignoreCancelled = true)
    public void onFlight(PlayerToggleFlightEvent event) {
        if (auth.isPending(event.getPlayer())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(ignoreCancelled = true)
    public void onVelocity(PlayerVelocityEvent event) {
        if (config.noPush() && auth.isPending(event.getPlayer())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(ignoreCancelled = true)
    public void onDamage(EntityDamageEvent event) {
        if (config.invulnerable() && event.getEntity() instanceof Player player && auth.isPending(player)) {
            event.setCancelled(true);
        }
    }

    @EventHandler(ignoreCancelled = true)
    public void onDamageByEntity(EntityDamageByEntityEvent event) {
        Player damager = playerBehind(event.getDamager());
        if (damager != null && auth.isPending(damager)) {
            event.setCancelled(true);
        }
    }

    private Player playerBehind(Entity damager) {
        if (damager instanceof Player player) {
            return player;
        }
        if (damager instanceof Projectile projectile
                && projectile.getShooter() instanceof Player shooter) {
            return shooter;
        }
        return null;
    }

    @EventHandler(ignoreCancelled = true)
    public void onTarget(EntityTargetEvent event) {
        if (!(event.getTarget() instanceof Player player) || !auth.isPending(player)) {
            return;
        }
        if (event.getReason() != EntityTargetEvent.TargetReason.TARGET_DIED
                && event.getReason() != EntityTargetEvent.TargetReason.FORGOT_TARGET) {
            event.setTarget(null);
            event.setCancelled(true);
        }
    }

    @EventHandler(ignoreCancelled = true)
    public void onFoodLevel(FoodLevelChangeEvent event) {
        if (event.getEntity() instanceof Player player && auth.isPending(player)) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onChat(AsyncChatEvent event) {
        if (config.blockChat() && auth.isPending(event.getPlayer())) {
            event.setCancelled(true);
            event.getPlayer().sendMessage(config.message("chat-blocked"));
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onCommand(PlayerCommandPreprocessEvent event) {
        if (!auth.isPending(event.getPlayer())) {
            return;
        }
        String raw = event.getMessage();
        int space = raw.indexOf(' ');
        String label = (space < 0 ? raw.substring(1) : raw.substring(1, space)).toLowerCase(Locale.ROOT);
        int colon = label.indexOf(':');
        if (colon >= 0 && label.substring(0, colon).equals("wauth")) {
            label = label.substring(colon + 1);
        }
        if (!config.allowedCommands().contains(label)) {
            event.setCancelled(true);
            event.getPlayer().sendMessage(config.message("command-blocked"));
        }
    }

    @EventHandler(ignoreCancelled = true)
    public void onInteract(PlayerInteractEvent event) {
        blockInteraction(event.getPlayer(), event);
    }

    @EventHandler(ignoreCancelled = true)
    public void onInteractEntity(PlayerInteractEntityEvent event) {
        blockInteraction(event.getPlayer(), event);
    }

    @EventHandler(ignoreCancelled = true)
    public void onDropItem(PlayerDropItemEvent event) {
        blockInteraction(event.getPlayer(), event);
    }

    @EventHandler(ignoreCancelled = true)
    public void onSwapHands(PlayerSwapHandItemsEvent event) {
        blockInteraction(event.getPlayer(), event);
    }

    @EventHandler(ignoreCancelled = true)
    public void onConsume(PlayerItemConsumeEvent event) {
        blockInteraction(event.getPlayer(), event);
    }

    @EventHandler(ignoreCancelled = true)
    public void onPickup(EntityPickupItemEvent event) {
        if (event.getEntity() instanceof Player player) {
            blockInteraction(player, event);
        }
    }

    @EventHandler(ignoreCancelled = true)
    public void onBlockBreak(BlockBreakEvent event) {
        blockInteraction(event.getPlayer(), event);
    }

    @EventHandler(ignoreCancelled = true)
    public void onBlockPlace(BlockPlaceEvent event) {
        blockInteraction(event.getPlayer(), event);
    }

    @EventHandler(ignoreCancelled = true)
    public void onInventoryOpen(InventoryOpenEvent event) {
        if (event.getPlayer() instanceof Player player) {
            blockInteraction(player, event);
        }
    }

    @EventHandler(ignoreCancelled = true)
    public void onInventoryClick(InventoryClickEvent event) {
        if (event.getWhoClicked() instanceof Player player) {
            blockInteraction(player, event);
        }
    }

    private void blockInteraction(Player player, org.bukkit.event.Cancellable event) {
        if (config.blockInteraction() && auth.isPending(player)) {
            event.setCancelled(true);
        }
    }

    @EventHandler(ignoreCancelled = true)
    public void onInventoryDrag(InventoryDragEvent event) {
        if (event.getWhoClicked() instanceof Player player) {
            blockInteraction(player, event);
        }
    }
}
