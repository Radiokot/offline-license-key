package ua.com.radiokot.license

import com.auth0.jwt.JWT
import java.security.interfaces.RSAPrivateKey
import java.util.*

/**
 * A factory producing the JWT keys from the given issuer.
 *
 * @see JwtLicenseKey
 */
class JwtLicenseKeyFactory(
    private val issuer: String,
    issuerPrivateKey: RSAPrivateKey,
) : OfflineLicenseKeyFactory {
    private val issuerAlgorithm = JwtLicenseKey.getAlgorithm(issuerPrivateKey)
    private val jwtBuilder = JWT.create().withIssuer(issuer)

    override fun issue(
        subject: String,
        hardware: String,
        features: Set<Int>,
        expiresAt: Date?,
    ): OfflineLicenseKey {
        val featuresBitSet = BitSet().apply {
            features.forEach { featureIndex ->
                set(featureIndex)
            }
        }

        val jwt = jwtBuilder
            .withSubject(subject)
            .withClaim(
                JwtLicenseKey.CLAIM_HARDWARE,
                hardware
            )
            .withArrayClaim(
                JwtLicenseKey.CLAIM_FEATURES,
                featuresBitSet.toLongArray().toTypedArray()
            )
            .apply {
                if (expiresAt != null) {
                    withExpiresAt(expiresAt)
                }
            }
            .sign(issuerAlgorithm)

        return JwtLicenseKey(
            issuer = issuer,
            subject = subject,
            hardware = hardware,
            features = features.toSet(),
            expiresAt = expiresAt,
            jwt = jwt,
        )
    }
}