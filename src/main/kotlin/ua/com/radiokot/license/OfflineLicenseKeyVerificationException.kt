/* Copyright 2024 Oleg Koretsky

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

sealed class OfflineLicenseKeyVerificationException(message: String?) : RuntimeException(message) {

    class InvalidFormat(message: String?) :
        OfflineLicenseKeyVerificationException(message)

    class AlgorithmMismatch(message: String?) :
        OfflineLicenseKeyVerificationException(message)

    class InvalidSignature(message: String?) :
        OfflineLicenseKeyVerificationException(message)

    class Expired(message: String?) :
        OfflineLicenseKeyVerificationException(message)

    class IssuerMismatch(message: String?) :
        OfflineLicenseKeyVerificationException(message)

    class HardwareMismatch(message: String?) :
        OfflineLicenseKeyVerificationException(message)

    class SubjectMismatch(message: String?) :
        OfflineLicenseKeyVerificationException(message)
}
