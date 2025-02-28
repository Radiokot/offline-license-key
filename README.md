# Offline License Key
[![Latest release](https://jitpack.io/v/ua.com.radiokot/offline-license-key.svg)](https://jitpack.io/#ua.com.radiokot/offline-license-key)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

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
    implementation 'ua.com.radiokot:offline-license-key:1.0.0'
}
```

## Usage
Start with `OfflineLicenseKeys.jwt` and follow the method docs.
Usage example can be found in `JwtLicenseKeyFactoryTest` and `JwtLicenseKeyVerifyingReaderTest`

[📖 Explore KDoc](https://javadoc.jitpack.io/ua/com/radiokot/offline-license-key/latest/javadoc/index.html)

|<!-- -->| Apps using Offline License Key |
|--------|:-------------------------------|
| <img src="https://raw.githubusercontent.com/Radiokot/photoprism-android-client/refs/heads/main/app/src/main/res/mipmap-hdpi/ic_launcher.png" alt="Icon" style="height: 28px;"/> |[Gallery for PhotoPrism](https://github.com/Radiokot/photoprism-android-client/tree/e6601acdb4db9c821abc4d7b793e264fb84dd070/app/src/main/java/ua/com/radiokot/photoprism/features/ext/key) uses the library to activate extensions|

## License
I reject the concept of intellectual property. Claiming ownership over information that can be replicated perfectly and endlessly is inherently flawed. Consequently, any efforts to uphold such form of ownership inevitably result in some people gaining unjustifiable control over other's tangible resources, such as computers, printing equipment, construction materials, etc.
When talking specifically about source code licensing – without a state violently enforcing [copyright monopolies](https://torrentfreak.com/language-matters-framing-the-copyright-monopoly-so-we-can-keep-our-liberties-130714/), it would be ludicrous to assume that a mere text file in a directory enables someone to restrict processing copies of this information by others on their very own computers.
However, there is [such a file](LICENSE) in this repository bearing the GPLv3 license. Why?

One would expect someone with such an attitude to not use the license at all, use a permissive license, or [explicitly unlicense](https://unlicense.org/).
But for me, to do so is to voluntarily limit my means of defense. To act as a gentleman with those who readily exploit state violence against you is to lose.
In a world where copyright monopolies are violently enforced, I choose GPLv3 for the software I really care for, because under the current circumstances this license is a tool that:
- Allows **others** to freely use, modify and distribute this software, without the risk of being sued;
- Enables **me** to pull all the valuable changes from public forks back to the trunk, also without the risk of being sued;
- **Knocks down a peg** individuals or companies willing to monopolize their use case or modifications of this software.
