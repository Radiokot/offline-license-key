package ua.com.radiokot.license

interface OfflineLicenseKeyFactory {
    fun issue(
        subject: String,
        hardware: String,
        features: Set<Int>,
    ): OfflineLicenseKey
}