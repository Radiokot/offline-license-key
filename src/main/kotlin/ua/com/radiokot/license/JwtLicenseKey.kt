package ua.com.radiokot.license

import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.interfaces.DecodedJWT
import java.security.interfaces.RSAKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*

/**
 * An [OfflineLicenseKey] in JWT (JSON Web Token) format.
 * Signing algorithm is RS256 (SHA256 with RSA).
 *
 * @see OfflineLicenseKeys.jwt
 */
class JwtLicenseKey(
    override val issuer: String,
    override val subject: String,
    override val hardware: String,
    override val features: Set<Int>,
    override val expiresAt: Date?,
    private val jwt: String,
) : OfflineLicenseKey {
    override val format: String = FORMAT

    constructor(decodedJWT: DecodedJWT) : this(
        issuer = decodedJWT.issuer,
        subject = decodedJWT.subject,
        hardware = decodedJWT.getClaim(CLAIM_HARDWARE).asString(),
        expiresAt = decodedJWT.expiresAt,
        features = decodedJWT.getClaim(CLAIM_FEATURES)
            .asArray(Number::class.java)
            .let { arrayOfNumbers ->
                LongArray(arrayOfNumbers.size) { i ->
                    arrayOfNumbers[i].toLong()
                }
            }
            .let(BitSet::valueOf)
            .setBitsSequence()
            .toSet(),
        jwt = decodedJWT.token,
    )

    override fun encode(): String =
        jwt

    companion object {
        const val FORMAT = "JWT"
        const val CLAIM_HARDWARE = "hw"
        const val CLAIM_FEATURES = "f"

        fun getAlgorithm(key: RSAKey): Algorithm =
            Algorithm.RSA256(key as? RSAPublicKey, key as? RSAPrivateKey)
    }
}
