package com.imdomestic.mc.router;

import com.velocitypowered.api.proxy.ProxyServer;
import com.viaversion.viaversion.api.Via;
import java.util.Optional;

/**
 * 告诉 Velocity 上的 Via 动态后端的协议版本。
 *
 * <p>不告诉的话，Via 要等下一轮探测（默认 60 秒）才知道新房间的版本，在那之前会把它当成
 * Velocity 支持的最低版本，翻译出来的包全是错的。Via 没装时不会加载这个类。
 */
final class ViaHook {
  private ViaHook() {}

  static Optional<ViaHook> create(ProxyServer proxy) {
    return proxy.getPluginManager().isLoaded("viaversion") ? Optional.of(new ViaHook()) : Optional.empty();
  }

  void setProtocol(String server, int protocol) {
    Via.proxyPlatform().protocolDetectorService().setProtocolVersion(server, protocol);
  }

  void forget(String server) {
    Via.proxyPlatform().protocolDetectorService().uncacheProtocolVersion(server);
  }
}
