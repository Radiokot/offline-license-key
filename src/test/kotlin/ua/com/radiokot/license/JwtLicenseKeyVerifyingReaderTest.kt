package ua.com.radiokot.license

import com.auth0.jwt.exceptions.IncorrectClaimException
import com.auth0.jwt.exceptions.SignatureVerificationException
import com.auth0.jwt.exceptions.TokenExpiredException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.security.KeyFactory
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.*
import kotlin.test.assertEquals

internal class JwtLicenseKeyVerifyingReaderTest {

    @Test
    fun readSuccessfully_IfNoExpirationDate() {
        val encodedKey = """
            eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJyYWRpb2tvdC5jb20udWEiLCJzdWIiOiJvbGVnQHJhZGlva290LmNvbS51YSIsImh3IjoiMTIzMzIxIiwiZiI6WzUyNSwxXX0.G5Tof9C7tffcjpRM19E0MW8LNDJIaP65uWwDLD-vlNL84nDqGuCzGApwCKSRrtNmFA-8SL1pYheRNfga_oMXOX5wk5_mk8ecLDUvPsyapjy_QgJiSpWw2ONEM_4ghNa6tKlYQxa4FwMGhOxrPSC6ak0CIYubAvUJt3a83Y7JWIFQcsVQt-y1EN6O-a3DsV-SSz6T2lMkhXbWziZBeL-lg72E9krOyh66X7vQc2XXFqTNeLRAjSXYRymTxYlX-RiEpQdJybJqPCPvHrgA48l2P_MoV2t4vnPTp1QpB2gKk6ODWmAIw4fJlIu8CxIXPvSH4F5PfZ3tlfOGgINtw6hQ-g
        """.trimIndent()
        val issuerPublicKey: RSAPublicKey = KeyFactory.getInstance("RSA")
            .generatePublic(
                X509EncodedKeySpec(
                    Base64.getMimeDecoder().decode(
                        """
                MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3XA6TWmfQv1sHjiP0JDg
                jbbhnNF3Je3YhZbdBB763uJpkbPl0pO2AshekMhn8ALPJ4sykyYBQsEuIKOroypi
                ycdK7sZzl9EgrD6eWvxLtckAVSuCR1AreVCVDfdu2Dzb5V4UF1JI2yAdNtxs3Wl4
                8af4Cjzy8YxM4Ah8VjzdOWZjFVb5A8oVkzOXYQiZQxpcWPHWAFZ5GiY9wisNaFHn
                boHndxaQ6iddFJLg2BmAToEpYH206qDyS6vIeEAUVE4/8IT3+JbJEns5dLKkPuO2
                YTmoHzADzf/r3y3vZrsg6Q9es8/Cw3K8dKFRlWTOC7c9L2sooBc403F53RYH5mBq
                xwIDAQAB
            """.trimIndent()
                    )
                )
            ) as RSAPublicKey

        val readKey = JwtLicenseKeyVerifyingReader(
            issuerPublicKey = issuerPublicKey,
            issuer = "radiokot.com.ua",
            hardware = "123321",
        ).read(encodedKey)

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

    @Test
    fun readSuccessfully_IfNotExpired() {
        val keyExpirationDate = Date(3707151200000)
        assert(Date() < keyExpirationDate) {
            "It's the year 2087 hence this test's vector is outdated"
        }

        val encodedKey = """
            eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJyYWRpb2tvdC5jb20udWEiLCJzdWIiOiJvbGVnQHJhZGlva290LmNvbS51YSIsImh3IjoiMTIzMzIxIiwiZiI6WzUyNSwxXSwiZXhwIjozNzA3MTUxMjAwfQ.W2v4xGAav6jHaV8nlA9aSW-gfVNpeFefsEDWvT-OLMfOXCK8baZvMLtUADI7Nuzq91VsS7XHMvc5pbuM7jviOzrrxilxzIiuskeaofaJS-1ExaGsVCOUcw0dC_tRRLmQyTzL3hnd6uhTs9gV66uRHSZZ9SERJNhsetlYGiOJV_0GliOc8_dbDCWih1iEU4yl8srGnLWBJFCRTAS2wCr2eRGsTvAYYrQEMV1816CFdQY6vwvBhayrBcCpEka-bcQrsXYGrrpr7IDQ2RXji_GLCVnD7Mu6AqRohIEh7j-UfLv__Cj80_sZmmzBpd5DWgdfMpblpFcix-4f_jqKmpakNQ
        """.trimIndent()
        val issuerPublicKey: RSAPublicKey = KeyFactory.getInstance("RSA")
            .generatePublic(
                X509EncodedKeySpec(
                    Base64.getMimeDecoder().decode(
                        """
                MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApV1sZFLNNdpq28TfybdT
                IsDK99kEUvA4YZsRaKdNOzct4isVvc2aruoIsThJVE6A8xenYz7n/XqlmCwrRYDE
                wky3v3lu29bPeR3mt915fsbVW5/lF3U76KaghnCQlyP1MercJ22cbINjbrksUFO/
                4pyiGvha9GQ3B6tinPQyOi+PZZoj2kab1C3Hx58jHEcXaJvcI+Ho1I6W9WF/7nlK
                lfqw8boCPUHoD3KLpiPRiHN97hsvvBKx2e45m3WNTzgrpMQIfCaqkOD8hsEiEWAi
                1djk/G5wIQ5XdH1TE64tOUlqtetF1+7tiPEYIApdBcIjFaPTkBgvXHmT/VDBe6+E
                bwIDAQAB
            """.trimIndent()
                    )
                )
            ) as RSAPublicKey

        val readKey = JwtLicenseKeyVerifyingReader(
            issuerPublicKey = issuerPublicKey,
            issuer = "radiokot.com.ua",
            hardware = "123321",
        ).read(encodedKey)

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
            keyExpirationDate,
            readKey.expiresAt
        )
    }

    @Test
    fun failToRead_IfExpired() {
        val encodedKey = """
            eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJyYWRpb2tvdC5jb20udWEiLCJzdWIiOiJvbGVnQHJhZGlva290LmNvbS51YSIsImh3IjoiMTIzMzIxIiwiZiI6WzUyNSwxXSwiZXhwIjoxNzA3MTUxMjAwfQ.E4BKbWpnJAgNTTlNB-LJWpNyjSvFJAZIL5zGZiiGWd6_34OAd1ZEvxbYBWlzTNzp1wdr2lWb0dsaKYAHQ8CzKyBzIRh7quGGbwm86s_09gxpE1w29U6pQOcErd-XxDbLu3gpl3ULeY5tDYJyj2O8sCfzEpR-KGF0_Ntlu-YWgwV1ZwZLu6XD1OTVEgxg4jZhmglN-c3WYqGrWy4tLbfxJaDFRiKym2YiFIPiBm9HLWG8poiawcDe6QPawXXO_rSZbHbwLVWf0dqNrc-x_wBTyWINTFlfEwuVQYCpRbH20RxC0pAp1fjCya00yaj4WIr5BOjxitX6PEjU9DG9b0Tv8A
        """.trimIndent()
        val issuerPublicKey: RSAPublicKey = KeyFactory.getInstance("RSA")
            .generatePublic(
                X509EncodedKeySpec(
                    Base64.getMimeDecoder().decode(
                        """
                MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApV1sZFLNNdpq28TfybdT
                IsDK99kEUvA4YZsRaKdNOzct4isVvc2aruoIsThJVE6A8xenYz7n/XqlmCwrRYDE
                wky3v3lu29bPeR3mt915fsbVW5/lF3U76KaghnCQlyP1MercJ22cbINjbrksUFO/
                4pyiGvha9GQ3B6tinPQyOi+PZZoj2kab1C3Hx58jHEcXaJvcI+Ho1I6W9WF/7nlK
                lfqw8boCPUHoD3KLpiPRiHN97hsvvBKx2e45m3WNTzgrpMQIfCaqkOD8hsEiEWAi
                1djk/G5wIQ5XdH1TE64tOUlqtetF1+7tiPEYIApdBcIjFaPTkBgvXHmT/VDBe6+E
                bwIDAQAB
            """.trimIndent()
                    )
                )
            ) as RSAPublicKey

        assertThrows<TokenExpiredException> {
            JwtLicenseKeyVerifyingReader(
                issuerPublicKey = issuerPublicKey,
            ).read(encodedKey)
        }
    }

    @Test
    fun failToRead_IfHardwareIsDifferent() {
        val encodedKey = """
            eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJyYWRpb2tvdC5jb20udWEiLCJzdWIiOiJvbGVnQHJhZGlva290LmNvbS51YSIsImh3IjoiMTIzMzIxIiwiZiI6WzUyNSwxXX0.G5Tof9C7tffcjpRM19E0MW8LNDJIaP65uWwDLD-vlNL84nDqGuCzGApwCKSRrtNmFA-8SL1pYheRNfga_oMXOX5wk5_mk8ecLDUvPsyapjy_QgJiSpWw2ONEM_4ghNa6tKlYQxa4FwMGhOxrPSC6ak0CIYubAvUJt3a83Y7JWIFQcsVQt-y1EN6O-a3DsV-SSz6T2lMkhXbWziZBeL-lg72E9krOyh66X7vQc2XXFqTNeLRAjSXYRymTxYlX-RiEpQdJybJqPCPvHrgA48l2P_MoV2t4vnPTp1QpB2gKk6ODWmAIw4fJlIu8CxIXPvSH4F5PfZ3tlfOGgINtw6hQ-g
        """.trimIndent()
        val issuerPublicKey: RSAPublicKey = KeyFactory.getInstance("RSA")
            .generatePublic(
                X509EncodedKeySpec(
                    Base64.getMimeDecoder().decode(
                        """
                MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3XA6TWmfQv1sHjiP0JDg
                jbbhnNF3Je3YhZbdBB763uJpkbPl0pO2AshekMhn8ALPJ4sykyYBQsEuIKOroypi
                ycdK7sZzl9EgrD6eWvxLtckAVSuCR1AreVCVDfdu2Dzb5V4UF1JI2yAdNtxs3Wl4
                8af4Cjzy8YxM4Ah8VjzdOWZjFVb5A8oVkzOXYQiZQxpcWPHWAFZ5GiY9wisNaFHn
                boHndxaQ6iddFJLg2BmAToEpYH206qDyS6vIeEAUVE4/8IT3+JbJEns5dLKkPuO2
                YTmoHzADzf/r3y3vZrsg6Q9es8/Cw3K8dKFRlWTOC7c9L2sooBc403F53RYH5mBq
                xwIDAQAB
            """.trimIndent()
                    )
                )
            ) as RSAPublicKey

        // TODO introduce special exceptions for verifiers.
        assertThrows<IncorrectClaimException> {
            JwtLicenseKeyVerifyingReader(
                issuerPublicKey = issuerPublicKey,
                issuer = "radiokot.com.ua",
                hardware = "some other device",
            ).read(encodedKey)
        }
    }

    @Test
    fun failToRead_IfIssuerNameIsDifferent() {
        val encodedKey = """
            eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJyYWRpb2tvdC5jb20udWEiLCJzdWIiOiJvbGVnQHJhZGlva290LmNvbS51YSIsImh3IjoiMTIzMzIxIiwiZiI6WzUyNSwxXX0.G5Tof9C7tffcjpRM19E0MW8LNDJIaP65uWwDLD-vlNL84nDqGuCzGApwCKSRrtNmFA-8SL1pYheRNfga_oMXOX5wk5_mk8ecLDUvPsyapjy_QgJiSpWw2ONEM_4ghNa6tKlYQxa4FwMGhOxrPSC6ak0CIYubAvUJt3a83Y7JWIFQcsVQt-y1EN6O-a3DsV-SSz6T2lMkhXbWziZBeL-lg72E9krOyh66X7vQc2XXFqTNeLRAjSXYRymTxYlX-RiEpQdJybJqPCPvHrgA48l2P_MoV2t4vnPTp1QpB2gKk6ODWmAIw4fJlIu8CxIXPvSH4F5PfZ3tlfOGgINtw6hQ-g
        """.trimIndent()
        val issuerPublicKey: RSAPublicKey = KeyFactory.getInstance("RSA")
            .generatePublic(
                X509EncodedKeySpec(
                    Base64.getMimeDecoder().decode(
                        """
                MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3XA6TWmfQv1sHjiP0JDg
                jbbhnNF3Je3YhZbdBB763uJpkbPl0pO2AshekMhn8ALPJ4sykyYBQsEuIKOroypi
                ycdK7sZzl9EgrD6eWvxLtckAVSuCR1AreVCVDfdu2Dzb5V4UF1JI2yAdNtxs3Wl4
                8af4Cjzy8YxM4Ah8VjzdOWZjFVb5A8oVkzOXYQiZQxpcWPHWAFZ5GiY9wisNaFHn
                boHndxaQ6iddFJLg2BmAToEpYH206qDyS6vIeEAUVE4/8IT3+JbJEns5dLKkPuO2
                YTmoHzADzf/r3y3vZrsg6Q9es8/Cw3K8dKFRlWTOC7c9L2sooBc403F53RYH5mBq
                xwIDAQAB
            """.trimIndent()
                    )
                )
            ) as RSAPublicKey

        assertThrows<IncorrectClaimException> {
            JwtLicenseKeyVerifyingReader(
                issuerPublicKey = issuerPublicKey,
                issuer = "some other issuer",
            ).read(encodedKey)
        }
    }

    @Test
    fun failToRead_IfIssuerKeyIsDifferent() {
        val encodedKey = """
            eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJyYWRpb2tvdC5jb20udWEiLCJzdWIiOiJvbGVnQHJhZGlva290LmNvbS51YSIsImh3IjoiMTIzMzIxIiwiZiI6WzUyNSwxXX0.G5Tof9C7tffcjpRM19E0MW8LNDJIaP65uWwDLD-vlNL84nDqGuCzGApwCKSRrtNmFA-8SL1pYheRNfga_oMXOX5wk5_mk8ecLDUvPsyapjy_QgJiSpWw2ONEM_4ghNa6tKlYQxa4FwMGhOxrPSC6ak0CIYubAvUJt3a83Y7JWIFQcsVQt-y1EN6O-a3DsV-SSz6T2lMkhXbWziZBeL-lg72E9krOyh66X7vQc2XXFqTNeLRAjSXYRymTxYlX-RiEpQdJybJqPCPvHrgA48l2P_MoV2t4vnPTp1QpB2gKk6ODWmAIw4fJlIu8CxIXPvSH4F5PfZ3tlfOGgINtw6hQ-g
        """.trimIndent()
        val issuerPublicKey: RSAPublicKey = KeyFactory.getInstance("RSA")
            .generatePublic(
                X509EncodedKeySpec(
                    Base64.getMimeDecoder().decode(
                        """
                MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAl7JnbMvRi+1YbtmKWXJX
                B4XRABXfpfbJO3uDMEoIt7dRMIMucsekwSvUq08NrfSTftDRjzmMuGS7JpgSFFO3
                lB4T1N4wjwmOGiEYUY8myY3XRFyLTyK5IX4c+2DQ3wX/ecED5Dak9JP4ghgo4pIo
                /Sd5/vsSAYAazsWycaR+S9n93HBXFgDVQq4SMw72VsunoTZA+ip2SBQ2rhtRzbdi
                p98RmZCnnppgFHZ1VwmMzadkmtBx6UJZ9unVFg48/h0fUhPuHIhOlr/UACQ5LMdF
                svjJHibc/Y2cE3RYBj/Wy9qmKdnm8H+8s/LcS6ULJGvF5mW0ppmzkq1qc9/Q/4s+
                5wIDAQAB
            """.trimIndent()
                    )
                )
            ) as RSAPublicKey

        assertThrows<SignatureVerificationException> {
            JwtLicenseKeyVerifyingReader(
                issuerPublicKey = issuerPublicKey,
                issuer = "radiokot.com.ua",
            ).read(encodedKey)
        }
    }
}