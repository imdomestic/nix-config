// 统一用 JDK 25 构建（Velocity 4.2 的 API 是 Java 25 字节码），各子项目用
// options.release 决定产物的目标版本：跑在 Paper 1.21.1（Java 21）上的是 21。
subprojects {
    apply(plugin = "java")

    group = "com.imdomestic.mc"
    version = "0.1.0"

    tasks.withType<JavaCompile>().configureEach {
        options.encoding = "UTF-8"
        // processing 那一项会对 Velocity 的注解报"没有处理器认领"，是误报。
        options.compilerArgs.add("-Xlint:all,-processing")
    }
}
