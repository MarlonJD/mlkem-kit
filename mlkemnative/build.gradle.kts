import org.gradle.api.publish.maven.MavenPublication
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("maven-publish")
    id("signing")
}

group = providers.gradleProperty("GROUP").get()
version = providers.gradleProperty("VERSION_NAME").get()

android {
    namespace = "io.github.marlonjd.mlkemnative"
    compileSdk = 36
    ndkVersion = "30.0.14904198"

    defaultConfig {
        minSdk = 23
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        externalNativeBuild {
            cmake {
                arguments += listOf("-DANDROID_STL=none")
                cFlags += listOf(
                    "-DMLK_CONFIG_PARAMETER_SET=768",
                    "-DMLK_CONFIG_NO_RANDOMIZED_API",
                )
            }
        }

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
            withJavadocJar()
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
        freeCompilerArgs.add("-Xconsistent-data-class-copy-visibility")
    }
}

dependencies {
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])

                groupId = "io.github.marlonjd"
                artifactId = "mlkem-native-android"
                version = providers.gradleProperty("VERSION_NAME").get()

                pom {
                    name.set("MLKEMNativeAndroid")
                    description.set("Android AAR wrapper for ML-KEM-768 using mlkem-native")
                    url.set("https://github.com/MarlonJD/MLKEMNativeAndroid")

                    licenses {
                        license {
                            name.set("MIT License")
                            url.set("https://opensource.org/license/mit")
                        }
                    }

                    developers {
                        developer {
                            id.set("marlonjd")
                            name.set("Marlon JD")
                        }
                    }

                    scm {
                        connection.set("scm:git:https://github.com/MarlonJD/MLKEMNativeAndroid.git")
                        developerConnection.set("scm:git:ssh://git@github.com:MarlonJD/MLKEMNativeAndroid.git")
                        url.set("https://github.com/MarlonJD/MLKEMNativeAndroid")
                    }
                }
            }
        }

        repositories {
            val releaseRepositoryUrl = providers.gradleProperty("mavenCentralUrl")
                .orElse(providers.environmentVariable("MAVEN_CENTRAL_URL"))
            if (releaseRepositoryUrl.isPresent) {
                maven {
                    name = "MavenCentral"
                    url = uri(releaseRepositoryUrl.get())
                    credentials {
                        username = providers.gradleProperty("mavenCentralUsername")
                            .orElse(providers.environmentVariable("MAVEN_CENTRAL_USERNAME"))
                            .orNull
                        password = providers.gradleProperty("mavenCentralPassword")
                            .orElse(providers.environmentVariable("MAVEN_CENTRAL_PASSWORD"))
                            .orNull
                    }
                }
            }
        }
    }

    signing {
        val remotePublishRequested = gradle.startParameter.taskNames.any { taskName ->
            taskName.startsWith("publish") &&
                taskName != "publishToMavenLocal" &&
                !taskName.endsWith("ToMavenLocal")
        }
        val signingKey = providers.gradleProperty("signingInMemoryKey")
            .orElse(providers.environmentVariable("SIGNING_KEY"))
            .orNull
        val signingPassword = providers.gradleProperty("signingInMemoryKeyPassword")
            .orElse(providers.environmentVariable("SIGNING_KEY_PASSWORD"))
            .orNull

        isRequired = remotePublishRequested

        if (signingKey != null) {
            useInMemoryPgpKeys(signingKey, signingPassword)
        }
        sign(publishing.publications["release"])
    }
}
