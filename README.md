# mlkem-kit

Pure Swift and pure Kotlin ML-KEM implementation monorepo.

## Platforms

- `platforms/swift`: SwiftPM package imported from
  `MarlonJD/MLKEMNativeSwift`.
- `platforms/android`: Gradle/Android package imported from
  `MarlonJD/MLKEMNativeAndroid`.

The platform implementations keep their ecosystem-native package structure and
release tooling. Shared vectors, benchmark formats, and protocol notes should
live at the repository root as this monorepo matures.

## Checks

```sh
cd platforms/swift && swift test
cd platforms/android && ./gradlew test
```
