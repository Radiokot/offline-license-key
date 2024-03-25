package ua.com.radiokot.license

/**
 * Provides suites to work with different
 * offline license key formats.
 */
object OfflineLicenseKeys {
    /**
     * A suite to work with keys in JWT (JSON Web Token) format.
     *
     * @see JwtLicenseKey
     */
    @JvmStatic
    @get:JvmName("jwt")
    val jwt = JwtLicenseKeySuite()
}
