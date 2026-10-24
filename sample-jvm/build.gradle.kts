plugins { kotlin("jvm"); application }

dependencies { implementation(project(":quick-tunnel")) }

kotlin { jvmToolchain(17) }

application { mainClass.set("io.github.kinotvapp.quicktunnel.sample.MainKt") }
