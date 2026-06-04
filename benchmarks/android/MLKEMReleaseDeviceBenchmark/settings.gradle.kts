pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "MLKEMReleaseDeviceBenchmark"
include(":app")
include(":mlkemnative")
project(":mlkemnative").projectDir = file("../../../platforms/android/mlkemnative")
