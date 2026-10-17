// 不依赖任何第三方库：Paper 和 Velocity 都会把它原样打进自己的 jar。
tasks.withType<JavaCompile>().configureEach {
    options.release.set(21)
}
