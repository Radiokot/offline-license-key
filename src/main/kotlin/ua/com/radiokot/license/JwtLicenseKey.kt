/* Copyright 2023, 2024 Oleg Koretsky

   This file is part of the Offline License Key library,
   a library for standalone issuance and verification of license keys
   unlocking paid features, without a license server.

   Offline License Key is free software: you can redistribute it
   and/or modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation, either version 3 of the License,
   or (at your option) any later version.

   Offline License Key is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
   See the GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with Offline License Key. If not, see <http://www.gnu.org/licenses/>.
*/
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
