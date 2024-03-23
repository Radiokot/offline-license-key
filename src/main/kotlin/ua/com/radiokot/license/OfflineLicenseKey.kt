package ua.com.radiokot.license

import java.util.*

/**
 * A decoded offline license key.
 */
interface OfflineLicenseKey {
    /**
     * Issuer (person, organization) of the key.
     */
    val issuer: String

    /**
     * Issuance subject (person, organization) for whom this key is issued for.
     */
    val subject: String

    /**
     * An identifier of the hardware this key is issued for.
     */
    val hardware: String

    /**
     * Non-negative indices of the features this key enables.
     *
     * @see hasFeature
     */
    val features: Set<Int>

    /**
     * Optional key (hence its features) expiration date.
     *
     * @see isPerpetual
     */
    val expiresAt: Date?

    /**
     * Format of the encoding of this key.
     *
     * @see encode
     */
    val format: String

    /**
     * True if the key has no expiration date.
     *
     * @see expiresAt
     */
    val isPerpetual: Boolean
        get() = expiresAt == null

    /**
     * @return true if the key enables a feature with the given [index].
     *
     * @param index non-negative index of the feature.
     *
     * @see features
     */
    fun hasFeature(index: Int): Boolean =
        index in features

    /**
     * @return this key encoded in its [format].
     */
    fun encode(): String
}