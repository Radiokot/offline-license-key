package ua.com.radiokot.license

import com.auth0.jwt.JWT

/**
 * A reader of JWT-encoded keys that only decodes them
 * without verifying validity.
 *
 * @see JwtLicenseKey
 */
class JwtLicenseKeyDecodingReader : OfflineLicenseKeyReader {
    override fun read(encoded: String): OfflineLicenseKey =
        JWT.decode(encoded)
            .let(::JwtLicenseKey)
}