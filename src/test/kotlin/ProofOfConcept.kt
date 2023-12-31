import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
import io.jsonwebtoken.Jwts
import org.junit.jupiter.api.Test
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*
import kotlin.streams.toList

class ProofOfConcept {
    @Test
    fun pocAuth0() {
        val issuerName = "radiokot.com.ua"
        val issuerKeys = KeyPairGenerator.getInstance("RSA")
            .apply { initialize(2048) }
            .genKeyPair()
        val issuerAlgorithm = Algorithm.RSA256(issuerKeys.public as RSAPublicKey, issuerKeys.private as RSAPrivateKey)
        val verifierAlgorithm = Algorithm.RSA256(issuerKeys.public as RSAPublicKey)

        val licenseSubject = "oleg@radiokot.com.ua"
        val licenseHardware = "123321"
        val licenseFeatures = arrayOf(0, 2, 3, 9, 64)

        val licenseKey: String = JWT
            .create()
            .withIssuer(issuerName)
            .withSubject(licenseSubject)
            .withClaim("hw", licenseHardware)
            .withArrayClaim(
                "f",
                BitSet().apply {
                    licenseFeatures.forEach { featureIndex ->
                        set(featureIndex)
                    }
                }.toLongArray().toTypedArray()
            )
            .sign(issuerAlgorithm)

        println("Issued license key: $licenseKey")
        println("Issued license key (short): ${licenseKey.substringAfter('.')}")

        val decodedLicenseKey = JWT
            .require(verifierAlgorithm)
            .withIssuer(issuerName)
            .withClaim("hw", licenseHardware)
            .build()
            .verify(licenseKey)

        println("Decoded license key subject: " + decodedLicenseKey.subject)
        println(
            "Decoded license key features: " +
                    decodedLicenseKey.getClaim("f")
                        .asArray(Number::class.java)
                        .map(Number::toLong)
                        .toLongArray()
                        .let(BitSet::valueOf)
                        .stream()
                        .toList()
                        .joinToString()
        )
    }

    @Test
    fun pocJjwt() {
        val issuerName = "radiokot.com.ua"
        val issuerKeys = KeyPairGenerator.getInstance("RSA")
            .apply { initialize(2048) }
            .genKeyPair()

        val licenseSubject = "oleg@radiokot.com.ua"
        val licenseHardware = "123321"
        val licenseFeatures = arrayOf(0, 2, 3, 9, 64)

        val licenseKey: String = Jwts.builder()
            .issuer(issuerName)
            .subject(licenseSubject)
            .claim("hw", licenseHardware)
            .claim(
                "f",
                BitSet().apply {
                    licenseFeatures.forEach { featureIndex ->
                        set(featureIndex)
                    }
                }.toLongArray().toTypedArray()
            )
            .signWith(issuerKeys.private)
            .compact()

        println("Issued license key: $licenseKey")
        println("Issued license key (short): ${licenseKey.substringAfter('.')}")

        val decodedLicenseKey: Jws<Claims> = Jwts.parser()
            .verifyWith(issuerKeys.public)
            .requireIssuer(issuerName)
            .require("hw", licenseHardware)
            .build()
            .parseSignedClaims(licenseKey)

        println("Decoded license key subject: " + decodedLicenseKey.payload.subject)
        println(
            "Decoded license key features: " +
                    (decodedLicenseKey.payload["f"] as ArrayList<Number>)
                        .map(Number::toLong)
                        .toLongArray()
                        .let(BitSet::valueOf)
                        .stream()
                        .toList()
                        .joinToString()
        )
    }

    @Test
    fun encodeKey() {
        val keypair = KeyPairGenerator.getInstance("RSA")
            .apply { initialize(2048) }
            .genKeyPair()
        val encoder = Base64.getMimeEncoder(64, "\n".toByteArray(Charsets.US_ASCII))

        println("-----BEGIN RSA PRIVATE KEY-----")
        println(encoder.encodeToString(keypair.private.encoded))
        println("-----END RSA PRIVATE KEY-----")

        println("-----BEGIN RSA PUBLIC KEY-----")
        println(encoder.encodeToString(keypair.public.encoded))
        println("-----END RSA PUBLIC KEY-----")
    }
}