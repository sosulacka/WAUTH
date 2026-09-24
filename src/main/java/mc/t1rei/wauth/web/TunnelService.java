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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.Set;
import java.util.function.Consumer;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class TunnelService {

    private static final Pattern URL_PATTERN =
            Pattern.compile("https://[a-z0-9-]+\\.trycloudflare\\.com");
    static String binaryResource(String os, String arch) {
        if (!arch.equalsIgnoreCase("amd64") && !arch.equalsIgnoreCase("x86_64"))
            throw new IllegalArgumentException("Unsupported cloudflared architecture: " + arch);
        String name = os.toLowerCase(java.util.Locale.ROOT);
        if (name.startsWith("windows")) return "bin/cloudflared-windows-amd64.exe";
        if (name.contains("linux")) return "bin/cloudflared-linux-amd64";
        throw new IllegalArgumentException("Unsupported cloudflared OS: " + os);
    }

    private final Logger logger;
    private final int localPort;
    private final Path dataFolder;
    private final Consumer<String> onUrl;

    private volatile Process process;
    private volatile boolean stopped;
    private volatile String url;

    public TunnelService(Logger logger, int localPort, Path dataFolder, Consumer<String> onUrl) {
        this.logger = logger;
        this.localPort = localPort;
        this.dataFolder = dataFolder;
        this.onUrl = onUrl;
    }

    public void start() {
        try {
            Path binary = extractBinary();
            ProcessBuilder pb = new ProcessBuilder(
                    binary.toString(),
                    "tunnel", "--no-autoupdate",
                    "--url", "http://127.0.0.1:" + localPort);
            pb.redirectErrorStream(true);
            process = pb.start();
            Thread reader = new Thread(this::pump, "wauth-tunnel");
            reader.setDaemon(true);
            reader.start();
            logger.info("2FA tunnel: cloudflared запущен, ждём https-адрес…");
        } catch (Exception exception) {
            logger.severe("2FA tunnel: не удалось запустить cloudflared: " + exception);
        }
    }

    public void stop() {
        stopped = true;
        Process p = process;
        if (p != null) {
            p.destroy();
            try {
                if (!p.waitFor(3, java.util.concurrent.TimeUnit.SECONDS)) {
                    p.destroyForcibly();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                p.destroyForcibly();
            }
        }
    }

    public String url() {
        return url;
    }

    private void pump() {
        Process p = process;
        if (p == null) {
            return;
        }
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (url == null) {
                    Matcher matcher = URL_PATTERN.matcher(line);
                    if (matcher.find()) {
                        url = matcher.group();
                        logger.info("2FA tunnel: сайт доступен по " + url);
                        if (onUrl != null) {
                            onUrl.accept(url);
                        }
                    }
                }
            }
        } catch (IOException exception) {
            if (!stopped) {
                logger.warning("2FA tunnel: чтение вывода прервано: " + exception);
            }
        }
        if (!stopped) {
            logger.warning("2FA tunnel: cloudflared завершился (код "
                    + (p.isAlive() ? "?" : p.exitValue()) + "). Сайт по туннелю недоступен.");
        }
    }

    private Path extractBinary() throws IOException {
        String resource = binaryResource(System.getProperty("os.name", ""), System.getProperty("os.arch", ""));
        Path dir = dataFolder.resolve("bin").toAbsolutePath();
        Files.createDirectories(dir);
        Path target = dir.resolve(resource.endsWith(".exe") ? "cloudflared.exe" : "cloudflared");
        try (InputStream in = TunnelService.class.getClassLoader().getResourceAsStream(resource)) {
            if (in == null) {
                throw new IOException("бинарь " + resource + " не найден в jar");
            }
            Files.copy(in, target, StandardCopyOption.REPLACE_EXISTING);
        }
        if (!resource.endsWith(".exe")) try {
            Set<PosixFilePermission> perms = EnumSet.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE, PosixFilePermission.GROUP_READ,
                    PosixFilePermission.GROUP_EXECUTE, PosixFilePermission.OTHERS_READ,
                    PosixFilePermission.OTHERS_EXECUTE);
            Files.setPosixFilePermissions(target, perms);
        } catch (UnsupportedOperationException ignored) {
            target.toFile().setExecutable(true, false);
        }
        return target;
    }
}

