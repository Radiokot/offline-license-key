package ua.com.radiokot.license

import org.junit.jupiter.api.Test
import java.util.*
import kotlin.test.assertEquals

internal class JwtLicenseKeyDecodingReaderTest {

    @Test
    fun readSuccessfully() {
        val encodedKey = """
            eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJyYWRpb2tvdC5jb20udWEiLCJzdWIiOiJvbGVnQHJhZGlva290LmNvbS51YSIsImh3IjoiMTIzMzIxIiwiZiI6WzUyNSwxXSwiZXhwIjoxNzA3MTUxMjAwfQ.E4BKbWpnJAgNTTlNB-LJWpNyjSvFJAZIL5zGZiiGWd6_34OAd1ZEvxbYBWlzTNzp1wdr2lWb0dsaKYAHQ8CzKyBzIRh7quGGbwm86s_09gxpE1w29U6pQOcErd-XxDbLu3gpl3ULeY5tDYJyj2O8sCfzEpR-KGF0_Ntlu-YWgwV1ZwZLu6XD1OTVEgxg4jZhmglN-c3WYqGrWy4tLbfxJaDFRiKym2YiFIPiBm9HLWG8poiawcDe6QPawXXO_rSZbHbwLVWf0dqNrc-x_wBTyWINTFlfEwuVQYCpRbH20RxC0pAp1fjCya00yaj4WIr5BOjxitX6PEjU9DG9b0Tv8A
        """.trimIndent()

        val readKey = JwtLicenseKeyDecodingReader().read(encodedKey)

        assertEquals(
            "radiokot.com.ua",
            readKey.issuer
        )
        assertEquals(
            "oleg@radiokot.com.ua",
            readKey.subject
        )
        assertEquals(
            "123321",
            readKey.hardware
        )
        assertEquals(
            setOf(0, 2, 3, 9, 64),
            readKey.features
        )
        assertEquals(
            Date(1707151200000),
            readKey.expiresAt
        )
    }
}