plugins {
    id("fabric-loom") version "1.18.4"
}

val minecraftVersion = "1.21.11"

repositories {
    maven("https://maven.fabricmc.net/")
    mavenCentral()
}

dependencies {
    minecraft("com.mojang:minecraft:$minecraftVersion")
    mappings(loom.officialMojangMappings())
    modImplementation("net.fabricmc:fabric-loader:0.19.5")
    // 和 k8s/apps/mc 里 bingo 运行时装的版本一致。
    modImplementation("net.fabricmc.fabric-api:fabric-api:0.141.1+$minecraftVersion")
    implementation(project(":agones-core"))
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(21)
}

tasks.processResources {
    filesMatching("fabric.mod.json") {
        expand("version" to project.version)
    }
}

// core 没有外部依赖也不碰 Minecraft，直接并进 mod jar，remap 时原样保留。
tasks.jar {
    from(project(":agones-core").sourceSets.main.get().output)
}

tasks.remapJar {
    archiveFileName.set("agones-fabric.jar")
}
