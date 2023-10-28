package ua.com.radiokot.license

interface OfflineLicenseKey {
    val issuer: String
    val subject: String
    val hardware: String
    val features: Set<Int>
    val format: String

    fun hasFeature(index: Int): Boolean =
        index in features

    fun encode(): String
}