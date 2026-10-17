dependencies {
    compileOnly("io.papermc.paper:paper-api:1.21.1-R0.1-SNAPSHOT")
    implementation(project(":agones-core"))
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(21)
}

tasks.processResources {
    filesMatching("plugin.yml") {
        expand("version" to project.version)
    }
}

// core 没有外部依赖，直接把它的 class 并进插件 jar，不需要 shadow。
tasks.jar {
    archiveFileName.set("agones-paper.jar")
    from(project(":agones-core").sourceSets.main.get().output)
}
