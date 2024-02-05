package ua.com.radiokot.license

import java.util.*

interface OfflineLicenseKeyFactory {
    fun issue(
        subject: String,
        hardware: String,
        features: Set<Int>,
        expiresAt: Date? = null,
    ): OfflineLicenseKey

    fun issue(
        source: OfflineLicenseKey,
        subject: String = source.subject,
        hardware: String = source.hardware,
        features: Set<Int> = source.features,
        expiresAt: Date? = source.expiresAt,
    ): OfflineLicenseKey =
        issue(
            subject = subject,
            hardware = hardware,
            features = features,
            expiresAt = expiresAt,
        )
}