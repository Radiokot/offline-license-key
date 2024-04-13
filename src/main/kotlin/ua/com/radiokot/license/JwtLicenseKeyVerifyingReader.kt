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
import com.auth0.jwt.exceptions.AlgorithmMismatchException
import com.auth0.jwt.exceptions.InvalidClaimException
import com.auth0.jwt.exceptions.JWTDecodeException
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
    private val subject: String? = null,
    private val hardware: String? = null,
) : OfflineLicenseKeyReader {
    private val jwtVerifier: JWTVerifier =
        JWT.require(JwtLicenseKey.getAlgorithm(issuerPublicKey)).run {
            issuer?.also(::withIssuer)
            subject?.also(::withSubject)
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
        } catch (e: JWTDecodeException) {
            throw OfflineLicenseKeyVerificationException.InvalidFormat(e.message)
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

                message.contains("'${PublicClaims.SUBJECT}'") ->
                    throw OfflineLicenseKeyVerificationException.SubjectMismatch(message)

                message.contains("'${JwtLicenseKey.CLAIM_HARDWARE}'") ->
                    throw OfflineLicenseKeyVerificationException.HardwareMismatch(message)

                else ->
                    throw e
            }
        }
}
