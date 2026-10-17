package com.imdomestic.mc.router;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Comparator;
import java.util.Optional;
import java.util.concurrent.Executors;
import org.slf4j.Logger;

/**
 * 只读的状态接口，给 QQ bot 之类的外部程序查在线玩家和房间：{@code GET /v1/status}。
 *
 * <p>私有房间只给类型、人数和成员，不给房间码：房间码就是进私有房间的凭据。字段的说明见
 * docs/minecraft-network-todo.md。
 */
final class StatusServer {
  private final ProxyServer proxy;
  private final Routes routes;
  private final HttpServer http;

  private StatusServer(ProxyServer proxy, Routes routes, HttpServer http) {
    this.proxy = proxy;
    this.routes = routes;
    this.http = http;
  }

  static StatusServer start(int port, ProxyServer proxy, Routes routes, Logger logger) throws IOException {
    HttpServer http = HttpServer.create(new InetSocketAddress(port), 0);
    StatusServer server = new StatusServer(proxy, routes, http);
    http.createContext("/v1/status", server::handle);
    http.setExecutor(Executors.newSingleThreadExecutor(r -> {
      Thread t = new Thread(r, "router-status");
      t.setDaemon(true);
      return t;
    }));
    http.start();
    logger.info("状态接口在 :{}/v1/status", port);
    return server;
  }

  void stop() {
    http.stop(0);
  }

  private void handle(HttpExchange exchange) throws IOException {
    try (exchange) {
      if (!"GET".equals(exchange.getRequestMethod()) || !"/v1/status".equals(exchange.getRequestURI().getPath())) {
        exchange.sendResponseHeaders(404, -1);
        return;
      }
      byte[] body = snapshot().toString().getBytes(StandardCharsets.UTF_8);
      exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
      exchange.sendResponseHeaders(200, body.length);
      try (OutputStream out = exchange.getResponseBody()) {
        out.write(body);
      }
    }
  }

  JsonObject snapshot() {
    JsonArray players = new JsonArray();
    proxy.getAllPlayers().stream().sorted(Comparator.comparing(Player::getUsername)).forEach(p -> {
      JsonObject o = new JsonObject();
      o.addProperty("name", p.getUsername());
      Optional<RegisteredServer> server = p.getCurrentServer().map(c -> c.getServer());
      Optional<Routes.Route> route = server.flatMap(routes::routeOf);
      o.addProperty("kind", route.map(Routes.Route::kind)
          .orElseGet(() -> server.map(s -> s.getServerInfo().getName()).orElse(null)));
      route.filter(r -> r.isRoom() && r.isPublic()).ifPresent(r -> o.addProperty("room", r.room()));
      players.add(o);
    });

    JsonArray rooms = new JsonArray();
    for (Routes.Route r : routes.rooms()) {
      JsonObject o = new JsonObject();
      o.addProperty("kind", r.kind());
      o.addProperty("visibility", r.isPublic() ? "public" : "private");
      if (r.isPublic()) {
        o.addProperty("code", r.room());
      }
      o.addProperty("phase", r.phase());
      o.addProperty("owner", r.ownerName());
      o.addProperty("softCap", routes.softCap(r));
      JsonArray members = new JsonArray();
      routes.server(r).ifPresent(s -> s.getPlayersConnected().stream()
          .map(Player::getUsername).sorted().forEach(members::add));
      o.add("players", members);
      rooms.add(o);
    }

    JsonObject root = new JsonObject();
    root.addProperty("online", proxy.getPlayerCount());
    root.add("players", players);
    root.add("rooms", rooms);
    return root;
  }
}
