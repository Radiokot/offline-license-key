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
