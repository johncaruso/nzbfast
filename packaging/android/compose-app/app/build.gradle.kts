plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "app.nzbfast.mobile"
    compileSdk = 36

    defaultConfig {
        applicationId = "app.nzbfast.mobile"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.0.1-test"
    }

    // The engine ships as libnzbfast.so and is exec'd from
    // nativeLibraryDir; that needs a real file on disk.
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }

    sourceSets {
        getByName("main") {
            // fetch-engine.sh copies the cargo-ndk slim binary here as
            // engine/arm64-v8a/libnzbfast.so (gitignored).
            jniLibs.srcDir("engine")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("androidx.media3:media3-exoplayer:1.5.1")
    implementation("androidx.media3:media3-ui:1.5.1")

    // Host-side tests: the app itself uses the platform org.json; the
    // JVM needs the standalone artifact to run the same parsers.
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}
