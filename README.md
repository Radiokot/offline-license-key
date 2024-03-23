# Offline license key
[![Latest release](https://jitpack.io/v/ua.com.radiokot/offline-license-key.svg)](https://jitpack.io/#ua.com.radiokot/offline-license-key)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Issue and verify standalone license keys unlocking paid features, without a license server.

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
        implementation 'ua.com.radiokot:offline-license-key:1.0.0-rc.3'
}
```

## Usage
⚒ Work in progress

Start with `OfflineLicenseKeys.jwt` and follow the Javadoc.