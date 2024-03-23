package ua.com.radiokot.license

import com.auth0.jwt.JWT
import com.auth0.jwt.exceptions.JWTVerificationException
import com.auth0.jwt.interfaces.JWTVerifier
import java.security.interfaces.RSAPublicKey

/**
 * A reader of JWT-encoded keys that verifies validity.
 *
 * @see JwtLicenseKey
 */
class JwtLicenseKeyVerifyingReader(
    issuerPublicKey: RSAPublicKey,
    private val issuer: String? = null,
    private val hardware: String? = null,
) : OfflineLicenseKeyReader {
    private val jwtVerifier: JWTVerifier =
        JWT.require(JwtLicenseKey.getAlgorithm(issuerPublicKey)).run {
            issuer?.also(::withIssuer)
            hardware?.also { withClaim(JwtLicenseKey.CLAIM_HARDWARE, it) }
            build()
        }

    /**
     * @throws JWTVerificationException if verification fails
     */
    override fun read(encoded: String): OfflineLicenseKey =
        jwtVerifier.verify(encoded)
            .let(::JwtLicenseKey)
}