package ua.com.radiokot.license

import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

class JwtLicenseKeySuite {
    fun factory(
        issuerPrivateKey: RSAPrivateKey,
        issuer: String,
    ) = JwtLicenseKeyFactory(
        issuer = issuer,
        issuerPrivateKey = issuerPrivateKey,
    )

    fun verifyingReader(
        issuerPublicKey: RSAPublicKey,
        issuer: String? = null,
        hardware: String? = null,
    ) = JwtLicenseKeyVerifyingReader(
        issuerPublicKey = issuerPublicKey,
        issuer = issuer,
        hardware = hardware,
    )

    fun decodingReader() = JwtLicenseKeyDecodingReader()
}