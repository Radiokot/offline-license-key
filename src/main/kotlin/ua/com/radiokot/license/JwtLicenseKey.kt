package ua.com.radiokot.license

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

    companion object {
        const val FORMAT = "JWT"
        const val CLAIM_HARDWARE = "hw"
        const val CLAIM_FEATURES = "f"
    }
}