package ua.com.radiokot.license

import com.auth0.jwt.JWT
import com.auth0.jwt.exceptions.JWTDecodeException

/**
 * A reader of JWT-encoded keys that only decodes them
 * without verifying validity.
 *
 * @see JwtLicenseKey
 * @see OfflineLicenseKeyVerificationException.InvalidFormat
 */
class JwtLicenseKeyDecodingReader : OfflineLicenseKeyReader {
    /**
     * @throws OfflineLicenseKeyVerificationException.InvalidFormat if the key can't be decoded.
     */
    override fun read(encoded: String): OfflineLicenseKey =
        try {
            JWT.decode(encoded)
                .let(::JwtLicenseKey)
        } catch (e: JWTDecodeException) {
            throw OfflineLicenseKeyVerificationException.InvalidFormat(e.message)
        }
}