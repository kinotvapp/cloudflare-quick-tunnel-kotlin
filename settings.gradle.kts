pluginManagement { repositories { google(); mavenCentral(); gradlePluginPortal() } }
dependencyResolutionManagement { repositories { google(); mavenCentral() } }
rootProject.name = "cloudflare-quick-tunnel-kotlin"
include(":quick-tunnel", ":sample-jvm", ":sample-android")
