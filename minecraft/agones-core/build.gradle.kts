// 只依赖 Gson，而且是 compileOnly：Paper 和 Fabric（Minecraft 本身）运行时都自带 Gson，
// 各平台把 core 原样打进自己的 jar。
dependencies {
    compileOnly("com.google.code.gson:gson:2.10.1")
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(21)
}
