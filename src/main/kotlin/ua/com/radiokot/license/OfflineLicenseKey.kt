package ua.com.radiokot.license

import java.util.*

interface OfflineLicenseKey {
    val issuer: String
    val subject: String
    val hardware: String
    val features: Set<Int>
    val expiresAt: Date?
    val format: String

    fun hasFeature(index: Int): Boolean =
        index in features

    fun encode(): String
}