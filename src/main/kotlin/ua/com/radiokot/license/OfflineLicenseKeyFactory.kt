package ua.com.radiokot.license

interface OfflineLicenseKeyFactory {
    fun issue(
        subject: String,
        hardware: String,
        features: Set<Int>,
    ): OfflineLicenseKey

    fun issue(
        source: OfflineLicenseKey,
        subject: String = source.subject,
        hardware: String = source.hardware,
        features: Set<Int> = source.features,
    ): OfflineLicenseKey =
        issue(
            subject = subject,
            hardware = hardware,
            features = features,
        )
}