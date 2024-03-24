# Offline license key
[![Latest release](https://jitpack.io/v/ua.com.radiokot/offline-license-key.svg)](https://jitpack.io/#ua.com.radiokot/offline-license-key)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Issue and verify standalone license keys unlocking paid features, without a license server.

The library is compatible with Android SDK version **21** and higher.
It comes with its own `java.util.Base64`.

## Dependency

Step 1. Ensure you have JitPack repo added to your project `build.gradle` file:
```groovy
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        mavenCentral()
        maven { url 'https://jitpack.io' }
    }
}
```

Step 2. Add the dependency
```groovy
dependencies {
    implementation 'ua.com.radiokot:offline-license-key:1.0.0-rc.5'
}
```

## Usage
⚒ Work in progress

Start with `OfflineLicenseKeys.jwt` and follow the method docs.
Usage example can be found in `JwtLicenseKeyFactoryTest` and `JwtLicenseKeyVerifyingReaderTest`

[📖 Explore KDoc](https://javadoc.jitpack.io/ua/com/radiokot/offline-license-key/latest/javadoc/index.html)
