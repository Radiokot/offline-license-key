package ua.com.radiokot.license

import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.interfaces.DecodedJWT
import ua.com.radiokot.license.extension.indicesSequence
import java.security.interfaces.RSAKey
import java.util.*

class JwtLicenseKey(
    issuer: String,
    subject: String,
    hardware: String,
    features: Set<Int>,
    expiresAt: Date?,
    jwt: String,
) :
    OfflineLicenseKey by EncodedOfflineLicenseKey(
        issuer = issuer,
        subject = subject,
        hardware = hardware,
        features = features,
        expiresAt = expiresAt,
        format = FORMAT,
        encoded = jwt
    ) {

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
            .indicesSequence()
            .toSet(),
        jwt = decodedJWT.token,
    )

    companion object {
        const val FORMAT = "JWT"
        const val CLAIM_HARDWARE = "hw"
        const val CLAIM_FEATURES = "f"

        fun getAlgorithm(key: RSAKey): Algorithm =
            Algorithm.RSA256(key)
    }
}