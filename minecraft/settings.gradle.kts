rootProject.name = "imdomestic-minecraft"

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
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
// Velocity 插件：按 Agones GameServer 动态注册后端、选大厅。
include("velocity-router")
