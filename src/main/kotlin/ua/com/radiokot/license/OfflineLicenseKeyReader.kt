package ua.com.radiokot.license

interface OfflineLicenseKeyReader {
    /**
     * @throws OfflineLicenseKeyVerificationException if the encoded key can't be read.
     */
    fun read(encoded: String): OfflineLicenseKey
}