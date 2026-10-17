# 大厅：itzg 的服务端镜像加上 Agones 插件。服务端 jar 不打进镜像（Mojang EULA 不允许
# 再分发），由 itzg 在启动时按 TYPE/VERSION/PAPER_BUILD 下载。
FROM itzg/minecraft-server:2026.9.2-java21

# itzg 启动时把 /plugins 同步进 /data/plugins。
COPY agones-paper.jar /plugins/agones-paper.jar
