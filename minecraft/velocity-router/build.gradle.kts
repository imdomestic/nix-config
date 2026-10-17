dependencies {
    compileOnly("com.velocitypowered:velocity-api:4.2.0")
    annotationProcessor("com.velocitypowered:velocity-api:4.2.0")
    // Via 是可选依赖：装了就告诉它动态后端的版本，没装就跳过。
    compileOnly("com.viaversion:viaversion-api:5.12.0")
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(25)
}

tasks.jar {
    archiveFileName.set("velocity-router.jar")
}
