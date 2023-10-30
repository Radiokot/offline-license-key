package ua.com.radiokot.license

interface OfflineLicenseKeyReader {
    fun read(encoded: String): OfflineLicenseKey
}