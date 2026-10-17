pluginManagement {
    repositories {
        maven("https://maven.fabricmc.net/")
        gradlePluginPortal()
    }
}

rootProject.name = "imdomestic-minecraft"

// 没声明仓库的子项目用这里的。Loom 会给 agones-fabric 自己加 Mojang 和 Fabric 的仓库，
// 所以不能用 FAIL_ON_PROJECT_REPOS。
dependencyResolutionManagement {
    repositories {
        mavenCentral()
        maven("https://repo.papermc.io/repository/maven-public/")
        maven("https://repo.viaversion.com/")
    }
}

// 平台无关的 Agones SDK 客户端和生命周期逻辑，被各个平台的插件打包进去。
include("agones-core")
// Paper 服务端插件：大厅等原版协议的后端。
include("agones-paper")
// Fabric 服务端 mod：bingo 等 Fabric 后端（1.21.11，混淆版，要 remap）。
include("agones-fabric")
// Velocity 插件：按 Agones GameServer 动态注册后端、选大厅。
include("velocity-router")
