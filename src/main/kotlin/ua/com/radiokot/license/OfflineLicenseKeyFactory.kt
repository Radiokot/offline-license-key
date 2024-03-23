package ua.com.radiokot.license

import java.util.*

interface OfflineLicenseKeyFactory {
    /**
     * Issues a new key.
     *
     * @param subject [OfflineLicenseKey.subject].
     * @param hardware [OfflineLicenseKey.hardware].
     * @param features [OfflineLicenseKey.features].
     * @param expiresAt [OfflineLicenseKey.expiresAt].
     */
    fun issue(
        subject: String,
        hardware: String,
        features: Set<Int>,
        expiresAt: Date? = null,
    ): OfflineLicenseKey

    /**
     * Issues a modified copy of the [source] key.
     *
     * @param source a key to use as a base.
     * @param subject override for source subject ([OfflineLicenseKey.subject]).
     * @param hardware override for source hardware ([OfflineLicenseKey.hardware]).
     * @param features override for source features ([OfflineLicenseKey.features]).
     * @param expiresAt override for source expiration date ([OfflineLicenseKey.expiresAt]).
     */
    fun copy(
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