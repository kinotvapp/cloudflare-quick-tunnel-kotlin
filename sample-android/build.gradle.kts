plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }

android {
    namespace = "io.github.kinotvapp.quicktunnel.sample"
    compileSdk = 35
    defaultConfig { applicationId = "io.github.kinotvapp.quicktunnel.sample"; minSdk = 24; targetSdk = 34; versionCode = 1; versionName = "0.1.0" }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17
        isCoreLibraryDesugaringEnabled = true // java.time (Kwik, the library) does not exist on Android 7
    }
    kotlinOptions { jvmTarget = "17" }
    buildTypes { release { isMinifyEnabled = true; proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro") } }
    packaging { resources.excludes += setOf("META-INF/INDEX.LIST", "META-INF/DEPENDENCIES") }
}

dependencies {
    implementation(project(":quick-tunnel"))
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.5")
}
