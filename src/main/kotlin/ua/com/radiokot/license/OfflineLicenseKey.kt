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

import java.util.*

/**
 * A decoded Offline License Key.
 */
interface OfflineLicenseKey {
    /**
     * Issuer (person, organization) of the key.
     */
    val issuer: String

    /**
     * Issuance subject (person, organization) for whom this key is issued for.
     */
    val subject: String

    /**
     * An identifier of the hardware this key is issued for.
     */
    val hardware: String

    /**
     * Non-negative indices of the features this key enables.
     *
     * @see hasFeature
     */
    val features: Set<Int>

    /**
     * Optional key (hence its features) expiration date.
     *
     * @see isPerpetual
     */
    val expiresAt: Date?

    /**
     * Format of the encoding of this key.
     *
     * @see encode
     */
    val format: String

    /**
     * True if the key has no expiration date.
     *
     * @see expiresAt
     */
    val isPerpetual: Boolean
        get() = expiresAt == null

    /**
     * @return true if the key enables a feature with the given [index].
     *
     * @param index non-negative index of the feature.
     *
     * @see features
     */
    fun hasFeature(index: Int): Boolean =
        index in features

    /**
     * @return this key encoded in its [format].
     */
    fun encode(): String
}
