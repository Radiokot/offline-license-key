package ua.com.radiokot.license

import com.auth0.jwt.interfaces.DecodedJWT
import java.util.*
import kotlin.streams.toList

class JwtLicenseKey(
    issuer: String,
    subject: String,
    hardware: String,
    features: Set<Int>,
    jwt: String,
) :
    OfflineLicenseKey by OfflineLicenseKeyImpl(
        issuer = issuer,
        subject = subject,
        hardware = hardware,
        features = features,
        format = FORMAT,
        encoded = jwt
    ) {

    constructor(decodedJWT: DecodedJWT) : this(
        issuer = decodedJWT.issuer,
        subject = decodedJWT.issuer,
        hardware = decodedJWT.getClaim(CLAIM_HARDWARE).asString(),
        features = decodedJWT.getClaim(CLAIM_FEATURES)
            .asArray(Number::class.java)
            .map(Number::toLong)
            .toLongArray()
            .let(BitSet::valueOf)
            // TODO: Get rid of Java 8 APIs for Android < 26
            .stream()
            .toList()
            .toSet(),
        jwt = decodedJWT.token,
    )

    companion object {
        const val FORMAT = "JWT"
        const val CLAIM_HARDWARE = "hw"
        const val CLAIM_FEATURES = "f"
    }
}