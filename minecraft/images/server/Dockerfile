# 运营网络的服务端：itzg 的镜像加上我们的 Agones 集成。服务端 jar 不打进镜像（Mojang EULA
# 不允许再分发），由 itzg 在启动时按 TYPE/VERSION 下载。
FROM itzg/minecraft-server:2026.9.2-java21

# 两种都放，由 TYPE 决定用哪个：Paper 一类从 /plugins 同步，Fabric 一类从 /mods 同步。
# 另一个目录里多出来的 jar 不会被加载。
COPY agones-paper.jar /plugins/agones-paper.jar
COPY agones-fabric.jar /mods/agones-fabric.jar
