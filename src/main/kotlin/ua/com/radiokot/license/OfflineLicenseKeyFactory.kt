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

interface OfflineLicenseKeyFactory {
    /**
     * Issues a new key.
     *
     * @param subject [OfflineLicenseKey.subject].
     * @param hardware [OfflineLicenseKey.hardware].
     * @param features [OfflineLicenseKey.features].
     * @param expiresAt [OfflineLicenseKey.expiresAt].
     */
    fun issue(
        subject: String,
        hardware: String,
        features: Set<Int>,
        expiresAt: Date? = null,
    ): OfflineLicenseKey

    /**
     * Issues a modified copy of the [source] key.
     *
     * @param source a key to use as a base.
     * @param subject override for source subject ([OfflineLicenseKey.subject]).
     * @param hardware override for source hardware ([OfflineLicenseKey.hardware]).
     * @param features override for source features ([OfflineLicenseKey.features]).
     * @param expiresAt override for source expiration date ([OfflineLicenseKey.expiresAt]).
     */
    fun copy(
        source: OfflineLicenseKey,
        subject: String = source.subject,
        hardware: String = source.hardware,
        features: Set<Int> = source.features,
        expiresAt: Date? = source.expiresAt,
    ): OfflineLicenseKey =
        issue(
            subject = subject,
            hardware = hardware,
            features = features,
            expiresAt = expiresAt,
        )
}
