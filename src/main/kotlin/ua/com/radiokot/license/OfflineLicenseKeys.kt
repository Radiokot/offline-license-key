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

/**
 * Provides suites to work with different
 * Offline License Key formats.
 */
object OfflineLicenseKeys {
    /**
     * A suite to work with keys in JWT (JSON Web Token) format.
     *
     * @see JwtLicenseKey
     */
    @JvmStatic
    @get:JvmName("jwt")
    val jwt = JwtLicenseKeySuite()
}
