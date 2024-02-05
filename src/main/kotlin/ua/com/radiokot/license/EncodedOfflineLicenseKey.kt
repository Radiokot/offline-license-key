package ua.com.radiokot.license

class EncodedOfflineLicenseKey(
    override val issuer: String,
    override val subject: String,
    override val hardware: String,
    override val features: Set<Int>,
    override val format: String,
    private val encoded: String,
) : OfflineLicenseKey {
    override fun encode(): String = encoded
}