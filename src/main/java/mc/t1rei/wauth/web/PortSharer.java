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

import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelPipeline;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.QueryStringDecoder;
import io.netty.util.ReferenceCountUtil;
import org.bukkit.Bukkit;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

public final class PortSharer {

    private static final String[] HTTP_PREFIXES = {
            "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "TRACE ", "CONNECT "
    };
    private static final int PEEK = 8;

    private final Logger logger;
    private final Router router;
    private final List<Channel> listeners = new ArrayList<>();
    private Acceptor acceptor;

    public PortSharer(Logger logger, Router router) {
        this.logger = logger;
        this.router = router;
    }

    public boolean install() {
        try {
            List<Channel> channels = findListenerChannels();
            if (channels.isEmpty()) {
                logger.warning("2FA: слушающие каналы сервера не найдены — общий порт недоступен.");
                return false;
            }
            acceptor = new Acceptor();
            for (Channel channel : channels) {
                channel.eventLoop().submit(() -> {
                    if (channel.pipeline().get(Acceptor.class) == null) {
                        channel.pipeline().addFirst("wauth-acceptor", acceptor);
                    }
                });
                listeners.add(channel);
            }
            logger.info("2FA: сайт подсажен на порт игрового сервера (каналов: " + listeners.size() + ").");
            return true;
        } catch (Throwable error) {
            logger.warning("2FA: не удалось занять порт сервера (" + error + ") — будет отдельный порт.");
            return false;
        }
    }

    public void uninstall() {
        for (Channel channel : listeners) {
            try {
                channel.eventLoop().submit(() -> {
                    if (channel.pipeline().context("wauth-acceptor") != null) {
                        channel.pipeline().remove("wauth-acceptor");
                    }
                });
            } catch (Throwable ignored) {
            }
        }
        listeners.clear();
    }

    private List<Channel> findListenerChannels() throws Exception {
        Object craftServer = Bukkit.getServer();
        Object mcServer = craftServer.getClass().getMethod("getServer").invoke(craftServer);

        Object connection = findFieldValueByType(mcServer, "ServerConnection");
        if (connection == null) {
            return List.of();
        }
        List<Channel> result = new ArrayList<>();
        for (Field field : connection.getClass().getDeclaredFields()) {
            if (!List.class.isAssignableFrom(field.getType())) {
                continue;
            }
            field.setAccessible(true);
            Object value = field.get(connection);
            if (!(value instanceof List<?> list)) {
                continue;
            }
            synchronized (list) {
                for (Object item : list) {
                    if (item instanceof ChannelFuture future && future.channel() != null) {
                        result.add(future.channel());
                    }
                }
            }
            if (!result.isEmpty()) {
                return result;
            }
        }
        return result;
    }

    private Object findFieldValueByType(Object owner, String marker) throws IllegalAccessException {
        Class<?> type = owner.getClass();
        while (type != null && type != Object.class) {
            for (Field field : type.getDeclaredFields()) {
                field.setAccessible(true);
                Object value = field.get(owner);
                if (value != null && value.getClass().getSimpleName().contains(marker)) {
                    return value;
                }
            }
            type = type.getSuperclass();
        }
        return null;
    }

    @io.netty.channel.ChannelHandler.Sharable
    private final class Acceptor extends ChannelInboundHandlerAdapter {
        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            if (msg instanceof Channel child) {
                child.pipeline().addFirst("wauth-detector", new Detector());
            }
            ctx.fireChannelRead(msg);
        }
    }

    private final class Detector extends ByteToMessageDecoder {
        @Override
        protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) {
            int available = in.readableBytes();
            if (available < 3) {
                return;
            }
            int peek = Math.min(available, PEEK);
            byte[] head = new byte[peek];
            in.getBytes(in.readerIndex(), head);
            String start = new String(head, StandardCharsets.US_ASCII);

            if (isHttp(start)) {
                switchToHttp(ctx);
            } else if (peek >= PEEK || !couldBeHttp(start)) {
                ctx.pipeline().remove(this);
            }
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            logger.warning("2FA: сбой детектора протокола: " + cause);
            ctx.close();
        }

        private void switchToHttp(ChannelHandlerContext ctx) {
            ChannelPipeline pipeline = ctx.pipeline();
            String selfName = ctx.name();
            List<String> existing = new ArrayList<>();
            for (java.util.Map.Entry<String, io.netty.channel.ChannelHandler> entry : pipeline) {
                existing.add(entry.getKey());
            }
            pipeline.addLast("wauth-http-codec", new HttpServerCodec());
            pipeline.addLast("wauth-http-timeout", new io.netty.handler.timeout.ReadTimeoutHandler(10));
            pipeline.addLast("wauth-http-agg", new HttpObjectAggregator(Router.MAX_BODY));
            pipeline.addLast("wauth-web", new WebHandler());
            for (String name : existing) {
                if (name.equals(selfName)) {
                    continue;
                }
                try {
                    if (pipeline.context(name) != null) {
                        pipeline.remove(name);
                    }
                } catch (Throwable ignored) {
                }
            }
            try {
                pipeline.remove(selfName);
            } catch (Throwable ignored) {
            }
        }
    }

    private final class WebHandler extends io.netty.channel.SimpleChannelInboundHandler<FullHttpRequest> {
        @Override
        protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
            if (!request.decoderResult().isSuccess()) {
                ctx.close();
                return;
            }
            QueryStringDecoder decoded = new QueryStringDecoder(request.uri());
            int q = request.uri().indexOf('?');
            String rawQuery = q >= 0 ? request.uri().substring(q + 1) : null;
            byte[] body = new byte[request.content().readableBytes()];
            request.content().getBytes(request.content().readerIndex(), body);
            String auth = request.headers().get(HttpHeaderNames.AUTHORIZATION);

            Router.Response response = router.route(
                    request.method().name(), decoded.path(), rawQuery, auth, body);

            ByteBuf content = ctx.alloc().buffer(response.body().length);
            content.writeBytes(response.body());
            DefaultFullHttpResponse full = new DefaultFullHttpResponse(
                    request.protocolVersion(),
                    HttpResponseStatus.valueOf(response.status()),
                    content);
            full.headers().set(HttpHeaderNames.CONTENT_TYPE, response.contentType());
            Router.SECURITY_HEADERS.forEach((name, value) -> full.headers().set(name, value));
            full.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes());
            boolean keepAlive = HttpUtil.isKeepAlive(request);
            if (keepAlive) {
                full.headers().set(HttpHeaderNames.CONNECTION, "keep-alive");
                ctx.writeAndFlush(full);
            } else {
                ctx.writeAndFlush(full).addListener(io.netty.channel.ChannelFutureListener.CLOSE);
            }
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            DefaultFullHttpResponse full = new DefaultFullHttpResponse(
                    io.netty.handler.codec.http.HttpVersion.HTTP_1_1,
                    HttpResponseStatus.INTERNAL_SERVER_ERROR);
            full.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, 0);
            ctx.writeAndFlush(full).addListener(io.netty.channel.ChannelFutureListener.CLOSE);
        }
    }

    private static boolean isHttp(String start) {
        for (String prefix : HTTP_PREFIXES) {
            if (start.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private static boolean couldBeHttp(String start) {
        for (String prefix : HTTP_PREFIXES) {
            if (prefix.startsWith(start) || start.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    @SuppressWarnings("unused")
    private static void release(Object msg) {
        ReferenceCountUtil.release(msg);
    }
}

