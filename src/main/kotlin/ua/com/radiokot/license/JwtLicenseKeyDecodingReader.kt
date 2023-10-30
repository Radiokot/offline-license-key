package ua.com.radiokot.license

import com.auth0.jwt.JWT

class JwtLicenseKeyDecodingReader : OfflineLicenseKeyReader {
    override fun read(encoded: String): OfflineLicenseKey =
        JWT.decode(encoded)
            .let(::JwtLicenseKey)
}