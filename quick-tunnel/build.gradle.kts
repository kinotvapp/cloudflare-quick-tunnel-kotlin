import java.time.Duration

plugins { kotlin("jvm") }

group = "io.github.kinotvapp"
version = "0.1.0"

dependencies {
    // Kwik (QUIC + TLS 1.3 in pure Java) is LGPL-3.0: see THIRD_PARTY_NOTICES.md.
    api("tech.kwik:kwik:0.12.1")
    implementation("tech.kwik:agent15:4.0") // Kwik's TLS 1.3 engine, also used directly for the TCP transport (Tls13.kt)
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
        // Fail the build on JDK APIs Android lacks (e.g. ByteBuffer.get(int, byte[]) is Java 13+); Kwik itself needs 11.
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
