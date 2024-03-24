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
