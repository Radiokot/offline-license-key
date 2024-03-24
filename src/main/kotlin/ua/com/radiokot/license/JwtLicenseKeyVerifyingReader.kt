package ua.com.radiokot.license

import com.auth0.jwt.JWT
import com.auth0.jwt.exceptions.AlgorithmMismatchException
import com.auth0.jwt.exceptions.InvalidClaimException
import com.auth0.jwt.exceptions.SignatureVerificationException
import com.auth0.jwt.exceptions.TokenExpiredException
import com.auth0.jwt.impl.PublicClaims
import com.auth0.jwt.interfaces.JWTVerifier
import java.security.interfaces.RSAPublicKey

/**
 * A reader of JWT-encoded keys that verifies validity.
 *
 * @see JwtLicenseKey
 * @see OfflineLicenseKeyVerificationException
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
     * @throws OfflineLicenseKeyVerificationException if the key can't be read or its verification failed.
     */
    override fun read(encoded: String): OfflineLicenseKey =
        try {
            jwtVerifier.verify(encoded)
                .let(::JwtLicenseKey)
        } catch (e: TokenExpiredException) {
            throw OfflineLicenseKeyVerificationException.Expired(e.message)
        } catch (e: SignatureVerificationException) {
            throw OfflineLicenseKeyVerificationException.InvalidSignature(e.message)
        } catch (e: AlgorithmMismatchException) {
            throw OfflineLicenseKeyVerificationException.AlgorithmMismatch(e.message)
        } catch (e: InvalidClaimException) {
            val message = e.message ?: ""
            when {
                message.contains("'${PublicClaims.ISSUER}'") ->
                    throw OfflineLicenseKeyVerificationException.IssuerMismatch(message)

                message.contains("'${JwtLicenseKey.CLAIM_HARDWARE}'") ->
                    throw OfflineLicenseKeyVerificationException.HardwareMismatch(message)

                else ->
                    throw e
            }
        }
}
