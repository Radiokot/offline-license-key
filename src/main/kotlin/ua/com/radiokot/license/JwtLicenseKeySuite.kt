package ua.com.radiokot.license

import com.auth0.jwt.exceptions.JWTVerificationException
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

/**
 * A suite to work with keys in JWT (JSON Web Token) format.
 *
 * @see JwtLicenseKey
 */
class JwtLicenseKeySuite {

    /**
     * @return a factory producing the keys from the given issuer.
     */
    fun factory(
        issuerPrivateKey: RSAPrivateKey,
        issuer: String,
    ) = JwtLicenseKeyFactory(
        issuer = issuer,
        issuerPrivateKey = issuerPrivateKey,
    )

    /**
     * @return a reader of encoded keys that verifies validity.
     *
     * @see JWTVerificationException
     */
    fun verifyingReader(
        issuerPublicKey: RSAPublicKey,
        issuer: String? = null,
        subject: String? = null,
        hardware: String? = null,
    ) = JwtLicenseKeyVerifyingReader(
        issuerPublicKey = issuerPublicKey,
        issuer = issuer,
        subject = subject,
        hardware = hardware,
    )

    /**
     * @return a reader of encoded keys that only decodes them
     * without verifying validity.
     */
    fun decodingReader() = JwtLicenseKeyDecodingReader()
}
