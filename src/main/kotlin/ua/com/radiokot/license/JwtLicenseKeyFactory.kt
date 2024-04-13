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
