plugins { kotlin("jvm") }

group = "io.github.kinotvapp"
version = "0.1.0"

dependencies {
    // Kwik (QUIC + TLS 1.3 in pure Java) is LGPL-3.0: see THIRD_PARTY_NOTICES.md.
    api("tech.kwik:kwik:0.12.1")
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

tasks.test { useJUnitPlatform() }
