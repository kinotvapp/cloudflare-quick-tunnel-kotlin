import java.time.Duration

plugins { kotlin("jvm") }

group = "io.github.kinotvapp"
version = "0.1.0"

dependencies {
    implementation("dnsjava:dnsjava:3.6.2")
    implementation("com.twitter:hpack:1.0.2") // HPACK decoding (Huffman + dynamic table) for the HTTP/2 fallback
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
    testImplementation(kotlin("test"))
}

java { sourceCompatibility = JavaVersion.VERSION_11; targetCompatibility = JavaVersion.VERSION_11 }

kotlin {
    jvmToolchain(17)
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11)
        // Fail the build on JDK APIs Android lacks (e.g. ByteBuffer.get(int, byte[]) is Java 13+).
        freeCompilerArgs.add("-Xjdk-release=11")
    }
}

// The JDK's TLS server rotates keys after this many bytes, which lets a test exercise KeyUpdate against a real peer.
val tlsTestProps = layout.buildDirectory.file("tls-test.security").get().asFile
tasks.test {
    useJUnitPlatform()
    timeout.set(Duration.ofMinutes(6)) // a test stuck on a blocking socket read must not hang the build
    doFirst {
        tlsTestProps.parentFile.mkdirs()
        tlsTestProps.writeText("jdk.tls.keyLimits=AES/GCM/NoPadding KeyUpdate 150000\n")
    }
    jvmArgs("-Djava.security.properties=${tlsTestProps.absolutePath}")
    if (project.hasProperty("tlsDebug")) { jvmArgs("-Djavax.net.debug=ssl:handshake"); testLogging { showStandardStreams = true } }
}

// The library ships no LGPL code: fail the build if a copyleft QUIC/TLS stack ever sneaks back into the runtime classpath.
val verifyNoLgpl by tasks.registering {
    val artifacts = configurations.runtimeClasspath.map { cfg -> cfg.incoming.artifactView { }.artifacts.map { it.id.componentIdentifier.displayName } }
    doLast {
        val banned = artifacts.get().filter { it.startsWith("tech.kwik") || "agent15" in it }
        check(banned.isEmpty()) { "LGPL dependencies on the runtime classpath: $banned" }
    }
}
tasks.check { dependsOn(verifyNoLgpl) }
