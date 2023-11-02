package ua.com.radiokot.license

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

internal class JwtLicenseKeyDecodingReaderTest {

    @Test
    fun read() {
        val encodedKey = """
            eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJyYWRpb2tvdC5jb20udWEiLCJzdWIiOiJvbGVnQHJhZGlva290LmNvbS51YSIsImh3IjoiMTIzMzIxIiwiZiI6WzUyNSwxXX0.Vqd1qwdkLJQ7bf5PI5Yo2ybZZKWYLn2-qSb3AmiyYRLErrjXp8ZK-nT-5F9jSkwTDy99BoxwBdtBVE6tLIU79SS6-9NVaSwECIenIc8TKBdLt8HTV0d1H6MkCt-mqp5GW2alMamgPe6J7D20Ki6DVnM_7tP0DVCEUy0pyj578l3vzh-cRaIX3GSKxEW8FM-S8Yi80UcmLPri6ay_exN9SmwB8WmIhbtTz1UNi-3BoyzLnZjyyd5VLHDTbJoAsDeyQ-_9NTHVVh0aRC8y5ZCrz9xFsODK-a2gJQ1blYE9u-9ZQENB1Txv8yG6o2NrLrpPhWoFPPlUyJRv6I3lRBWRKg
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
    }
}