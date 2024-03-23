package ua.com.radiokot.license

import org.junit.jupiter.api.Test
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue


internal class JwtLicenseKeyFactoryTest {
    @Test
    fun issueSuccessfully() {
        val issuerName = "radiokot.com.ua"
        val issuerKey = KeyFactory.getInstance("RSA")
            .generatePrivate(
                PKCS8EncodedKeySpec(
                    Base64.getMimeDecoder().decode(
                        """
                MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQClXWxkUs012mrb
                xN/Jt1MiwMr32QRS8DhhmxFop007Ny3iKxW9zZqu6gixOElUToDzF6djPuf9eqWY
                LCtFgMTCTLe/eW7b1s95Hea33Xl+xtVbn+UXdTvopqCGcJCXI/Ux6twnbZxsg2Nu
                uSxQU7/inKIa+Fr0ZDcHq2Kc9DI6L49lmiPaRpvULcfHnyMcRxdom9wj4ejUjpb1
                YX/ueUqV+rDxugI9QegPcoumI9GIc33uGy+8ErHZ7jmbdY1POCukxAh8JqqQ4PyG
                wSIRYCLV2OT8bnAhDld0fVMTri05SWq160XX7u2I8RggCl0FwiMVo9OQGC9ceZP9
                UMF7r4RvAgMBAAECggEARyUekTseluDVwJ+/OGXrGrSfnmp79cLsPvIcV05DaAqh
                bwDiZbqjpkWCX9y7j84GpI+0sHpMDT5LKGE4bLqt7HpdQ7/W9jZBJPa8YLakouqg
                uL7eLW1+zOWDgtPDIYOS5lsJRN1fwz/z85sveY/OqoyBIeFgIG1NT7toveZCBc3n
                CijR9z+q9G6njOUvxB6BfNyrxlaNCGEGt9dRmNzYR6Wfivdmloygx1rbQlrOhXg+
                1U+rIWAR6Hem4HPvGgeXx5/VmLzqWKnH/hp5s9KD/TfOY+vDN4qs1IwOapENkaen
                ocz3nmgI/KFFGm6rWT6CchyPt3aGXYVJH8sQogCbIQKBgQDcXJyMvtfueTYyqQOR
                5UpopRgGATNQrj8953IhC/dPhk1KNS4V4mAaxJVD+MCXRaLtQft4Js3am1Thmngf
                DKiMOSMMdycaAkqxggzvlwUHips2XcLBisbXi52K3qBdNlx5Fk4XqyHgI1d82MYH
                8YJmQVLufyERgD/Z1mrKoQ2ohQKBgQDAG9cqX3CLsDmuEtWPUH9WX5Y1CpUkRWpE
                Yc8uN9S8vIes0shEsnMvkSQ4VybcRQFDhT3kiMh1+28veRDBaJjUtHLHIu/rlwLy
                u3dLhBZAOx4y2m3gv1Y9teBx92RkO9LR8RFrOtvgESRb3wnhvIaq/fHMu8f11pl4
                vB+9t6XFYwKBgCCt302EE9O6yA3VQMFHJrTEHv7s+KYzYQ+WHjfGZYO2oAmsP0xh
                iO0PUC+HWVBVtGbJDTjxUD/mHz1hwgSgxPIemxMDLJpP0rHmXnK9i7JlnMUAPJyl
                Lv3SJ6frgg6wvB/87dHWwCxUMWpDX4LYDwWJFHpoAghtY4qzoJyyK6tdAoGARGwm
                EJN5lGcpxBQ1OBwlnm/hIfco84g9tylXD1EXVjmX4TgZ2E3utKxvSBnSX3W8Y34b
                c0A8lbj9+tyV2S0V8fxrPP32keRxSl72uFDNVAc6VEZ0CC5d2xDiZfUFLqYYCmpg
                F98Y3Q998bLY5Cuvk0trSc5ABBFxDA2FCJ9WTZ0CgYBw8u7qfs6vFRQdcJJnCvkC
                DI3Z1SdJisijiiQVD1yaivVrC6jSBg0ufz1H3aR1gEzFvRIGAFdifB2VRiXquSkG
                PuYVnO/11HLnMgrgbCm0p6xGroJJYGY4w3C+80etsO61nXaVdOLZS5f535CHPYXd
                oXEDDMnbblI4/6fKsuzlEQ==
            """.trimIndent()
                    )
                )
            )

        val licenseSubject = "oleg@radiokot.com.ua"
        val licenseHardware = "123321"
        val licenseFeatures = setOf(0, 2, 3, 9, 64)
        val expirationDate = Date(1707151200000)

        val issuedKey =
            OfflineLicenseKeys.jwt.factory(
                issuer = issuerName,
                issuerPrivateKey = issuerKey as RSAPrivateKey,
            )
                .issue(
                    subject = licenseSubject,
                    hardware = licenseHardware,
                    features = licenseFeatures,
                    expiresAt = expirationDate,
                )

        assertEquals(
            "JWT",
            issuedKey.format
        )
        assertEquals(
            issuerName,
            issuedKey.issuer
        )
        assertEquals(
            licenseSubject,
            issuedKey.subject,
        )
        assertEquals(
            licenseHardware,
            issuedKey.hardware,
        )
        assertEquals(
            licenseFeatures,
            issuedKey.features
        )
        licenseFeatures.forEach { feature ->
            assertTrue(issuedKey.hasFeature(feature))
        }
        assertEquals(
            expirationDate,
            issuedKey.expiresAt
        )
        assertFalse(
            issuedKey.isPerpetual
        )
        assertEquals(
            """
                eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJyYWRpb2tvdC5jb20udWEiLCJzdWIiOiJvbGVnQHJhZGlva290LmNvbS51YSIsImh3IjoiMTIzMzIxIiwiZiI6WzUyNSwxXSwiZXhwIjoxNzA3MTUxMjAwfQ.E4BKbWpnJAgNTTlNB-LJWpNyjSvFJAZIL5zGZiiGWd6_34OAd1ZEvxbYBWlzTNzp1wdr2lWb0dsaKYAHQ8CzKyBzIRh7quGGbwm86s_09gxpE1w29U6pQOcErd-XxDbLu3gpl3ULeY5tDYJyj2O8sCfzEpR-KGF0_Ntlu-YWgwV1ZwZLu6XD1OTVEgxg4jZhmglN-c3WYqGrWy4tLbfxJaDFRiKym2YiFIPiBm9HLWG8poiawcDe6QPawXXO_rSZbHbwLVWf0dqNrc-x_wBTyWINTFlfEwuVQYCpRbH20RxC0pAp1fjCya00yaj4WIr5BOjxitX6PEjU9DG9b0Tv8A
            """.trimIndent(),
            issuedKey.encode()
        )
    }

    @Test
    fun issueSuccessfully_IfNoExpirationDate() {
        val issuerName = "radiokot.com.ua"
        val issuerKey = KeyFactory.getInstance("RSA")
            .generatePrivate(
                PKCS8EncodedKeySpec(
                    Base64.getMimeDecoder().decode(
                        """
                MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQClXWxkUs012mrb
                xN/Jt1MiwMr32QRS8DhhmxFop007Ny3iKxW9zZqu6gixOElUToDzF6djPuf9eqWY
                LCtFgMTCTLe/eW7b1s95Hea33Xl+xtVbn+UXdTvopqCGcJCXI/Ux6twnbZxsg2Nu
                uSxQU7/inKIa+Fr0ZDcHq2Kc9DI6L49lmiPaRpvULcfHnyMcRxdom9wj4ejUjpb1
                YX/ueUqV+rDxugI9QegPcoumI9GIc33uGy+8ErHZ7jmbdY1POCukxAh8JqqQ4PyG
                wSIRYCLV2OT8bnAhDld0fVMTri05SWq160XX7u2I8RggCl0FwiMVo9OQGC9ceZP9
                UMF7r4RvAgMBAAECggEARyUekTseluDVwJ+/OGXrGrSfnmp79cLsPvIcV05DaAqh
                bwDiZbqjpkWCX9y7j84GpI+0sHpMDT5LKGE4bLqt7HpdQ7/W9jZBJPa8YLakouqg
                uL7eLW1+zOWDgtPDIYOS5lsJRN1fwz/z85sveY/OqoyBIeFgIG1NT7toveZCBc3n
                CijR9z+q9G6njOUvxB6BfNyrxlaNCGEGt9dRmNzYR6Wfivdmloygx1rbQlrOhXg+
                1U+rIWAR6Hem4HPvGgeXx5/VmLzqWKnH/hp5s9KD/TfOY+vDN4qs1IwOapENkaen
                ocz3nmgI/KFFGm6rWT6CchyPt3aGXYVJH8sQogCbIQKBgQDcXJyMvtfueTYyqQOR
                5UpopRgGATNQrj8953IhC/dPhk1KNS4V4mAaxJVD+MCXRaLtQft4Js3am1Thmngf
                DKiMOSMMdycaAkqxggzvlwUHips2XcLBisbXi52K3qBdNlx5Fk4XqyHgI1d82MYH
                8YJmQVLufyERgD/Z1mrKoQ2ohQKBgQDAG9cqX3CLsDmuEtWPUH9WX5Y1CpUkRWpE
                Yc8uN9S8vIes0shEsnMvkSQ4VybcRQFDhT3kiMh1+28veRDBaJjUtHLHIu/rlwLy
                u3dLhBZAOx4y2m3gv1Y9teBx92RkO9LR8RFrOtvgESRb3wnhvIaq/fHMu8f11pl4
                vB+9t6XFYwKBgCCt302EE9O6yA3VQMFHJrTEHv7s+KYzYQ+WHjfGZYO2oAmsP0xh
                iO0PUC+HWVBVtGbJDTjxUD/mHz1hwgSgxPIemxMDLJpP0rHmXnK9i7JlnMUAPJyl
                Lv3SJ6frgg6wvB/87dHWwCxUMWpDX4LYDwWJFHpoAghtY4qzoJyyK6tdAoGARGwm
                EJN5lGcpxBQ1OBwlnm/hIfco84g9tylXD1EXVjmX4TgZ2E3utKxvSBnSX3W8Y34b
                c0A8lbj9+tyV2S0V8fxrPP32keRxSl72uFDNVAc6VEZ0CC5d2xDiZfUFLqYYCmpg
                F98Y3Q998bLY5Cuvk0trSc5ABBFxDA2FCJ9WTZ0CgYBw8u7qfs6vFRQdcJJnCvkC
                DI3Z1SdJisijiiQVD1yaivVrC6jSBg0ufz1H3aR1gEzFvRIGAFdifB2VRiXquSkG
                PuYVnO/11HLnMgrgbCm0p6xGroJJYGY4w3C+80etsO61nXaVdOLZS5f535CHPYXd
                oXEDDMnbblI4/6fKsuzlEQ==
            """.trimIndent()
                    )
                )
            )

        val licenseSubject = "oleg@radiokot.com.ua"
        val licenseHardware = "123321"
        val licenseFeatures = setOf(0, 2, 3, 9, 64)

        val issuedKey =
            OfflineLicenseKeys.jwt.factory(
                issuer = issuerName,
                issuerPrivateKey = issuerKey as RSAPrivateKey,
            )
                .issue(
                    subject = licenseSubject,
                    hardware = licenseHardware,
                    features = licenseFeatures,
                )

        assertEquals(
            "JWT",
            issuedKey.format
        )
        assertEquals(
            issuerName,
            issuedKey.issuer
        )
        assertEquals(
            licenseSubject,
            issuedKey.subject,
        )
        assertEquals(
            licenseHardware,
            issuedKey.hardware,
        )
        assertEquals(
            licenseFeatures,
            issuedKey.features
        )
        licenseFeatures.forEach { feature ->
            assertTrue(issuedKey.hasFeature(feature))
        }
        assertNull(
            issuedKey.expiresAt
        )
        assertTrue(
            issuedKey.isPerpetual
        )
        assertEquals(
            """
                eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJyYWRpb2tvdC5jb20udWEiLCJzdWIiOiJvbGVnQHJhZGlva290LmNvbS51YSIsImh3IjoiMTIzMzIxIiwiZiI6WzUyNSwxXX0.Vqd1qwdkLJQ7bf5PI5Yo2ybZZKWYLn2-qSb3AmiyYRLErrjXp8ZK-nT-5F9jSkwTDy99BoxwBdtBVE6tLIU79SS6-9NVaSwECIenIc8TKBdLt8HTV0d1H6MkCt-mqp5GW2alMamgPe6J7D20Ki6DVnM_7tP0DVCEUy0pyj578l3vzh-cRaIX3GSKxEW8FM-S8Yi80UcmLPri6ay_exN9SmwB8WmIhbtTz1UNi-3BoyzLnZjyyd5VLHDTbJoAsDeyQ-_9NTHVVh0aRC8y5ZCrz9xFsODK-a2gJQ1blYE9u-9ZQENB1Txv8yG6o2NrLrpPhWoFPPlUyJRv6I3lRBWRKg
            """.trimIndent(),
            issuedKey.encode()
        )
    }

    @Test
    fun copySuccessfully() {
        val issuerKey = KeyFactory.getInstance("RSA")
            .generatePrivate(
                PKCS8EncodedKeySpec(
                    Base64.getMimeDecoder().decode(
                        """
                MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQClXWxkUs012mrb
                xN/Jt1MiwMr32QRS8DhhmxFop007Ny3iKxW9zZqu6gixOElUToDzF6djPuf9eqWY
                LCtFgMTCTLe/eW7b1s95Hea33Xl+xtVbn+UXdTvopqCGcJCXI/Ux6twnbZxsg2Nu
                uSxQU7/inKIa+Fr0ZDcHq2Kc9DI6L49lmiPaRpvULcfHnyMcRxdom9wj4ejUjpb1
                YX/ueUqV+rDxugI9QegPcoumI9GIc33uGy+8ErHZ7jmbdY1POCukxAh8JqqQ4PyG
                wSIRYCLV2OT8bnAhDld0fVMTri05SWq160XX7u2I8RggCl0FwiMVo9OQGC9ceZP9
                UMF7r4RvAgMBAAECggEARyUekTseluDVwJ+/OGXrGrSfnmp79cLsPvIcV05DaAqh
                bwDiZbqjpkWCX9y7j84GpI+0sHpMDT5LKGE4bLqt7HpdQ7/W9jZBJPa8YLakouqg
                uL7eLW1+zOWDgtPDIYOS5lsJRN1fwz/z85sveY/OqoyBIeFgIG1NT7toveZCBc3n
                CijR9z+q9G6njOUvxB6BfNyrxlaNCGEGt9dRmNzYR6Wfivdmloygx1rbQlrOhXg+
                1U+rIWAR6Hem4HPvGgeXx5/VmLzqWKnH/hp5s9KD/TfOY+vDN4qs1IwOapENkaen
                ocz3nmgI/KFFGm6rWT6CchyPt3aGXYVJH8sQogCbIQKBgQDcXJyMvtfueTYyqQOR
                5UpopRgGATNQrj8953IhC/dPhk1KNS4V4mAaxJVD+MCXRaLtQft4Js3am1Thmngf
                DKiMOSMMdycaAkqxggzvlwUHips2XcLBisbXi52K3qBdNlx5Fk4XqyHgI1d82MYH
                8YJmQVLufyERgD/Z1mrKoQ2ohQKBgQDAG9cqX3CLsDmuEtWPUH9WX5Y1CpUkRWpE
                Yc8uN9S8vIes0shEsnMvkSQ4VybcRQFDhT3kiMh1+28veRDBaJjUtHLHIu/rlwLy
                u3dLhBZAOx4y2m3gv1Y9teBx92RkO9LR8RFrOtvgESRb3wnhvIaq/fHMu8f11pl4
                vB+9t6XFYwKBgCCt302EE9O6yA3VQMFHJrTEHv7s+KYzYQ+WHjfGZYO2oAmsP0xh
                iO0PUC+HWVBVtGbJDTjxUD/mHz1hwgSgxPIemxMDLJpP0rHmXnK9i7JlnMUAPJyl
                Lv3SJ6frgg6wvB/87dHWwCxUMWpDX4LYDwWJFHpoAghtY4qzoJyyK6tdAoGARGwm
                EJN5lGcpxBQ1OBwlnm/hIfco84g9tylXD1EXVjmX4TgZ2E3utKxvSBnSX3W8Y34b
                c0A8lbj9+tyV2S0V8fxrPP32keRxSl72uFDNVAc6VEZ0CC5d2xDiZfUFLqYYCmpg
                F98Y3Q998bLY5Cuvk0trSc5ABBFxDA2FCJ9WTZ0CgYBw8u7qfs6vFRQdcJJnCvkC
                DI3Z1SdJisijiiQVD1yaivVrC6jSBg0ufz1H3aR1gEzFvRIGAFdifB2VRiXquSkG
                PuYVnO/11HLnMgrgbCm0p6xGroJJYGY4w3C+80etsO61nXaVdOLZS5f535CHPYXd
                oXEDDMnbblI4/6fKsuzlEQ==
            """.trimIndent()
                    )
                )
            )

        val factory = OfflineLicenseKeys.jwt.factory(
            issuer = "issuer",
            issuerPrivateKey = issuerKey as RSAPrivateKey,
        )

        val issuedKey = factory.issue(
            subject = "subject",
            hardware = "hardware",
            features = setOf(0, 2, 3, 9, 64),
        )

        val completeCopy = factory.copy(
            source = issuedKey,
        )

        assertEquals(issuedKey.encode(), completeCopy.encode())

        val editedSubject = "eSubject"
        val editedHardware = "eHardware"
        val editedFeatures = setOf(1, 2, 3, 9, 64)
        val editedExpirationDate = Date(1707151200000)

        val editedCopy = factory.copy(
            source = issuedKey,
            subject = editedSubject,
            hardware = editedHardware,
            features = editedFeatures,
            expiresAt = editedExpirationDate,
        )

        assertEquals(
            editedSubject,
            editedCopy.subject,
        )
        assertEquals(
            editedHardware,
            editedCopy.hardware,
        )
        assertEquals(
            editedFeatures,
            editedCopy.features
        )
        assertEquals(
            editedExpirationDate,
            editedCopy.expiresAt
        )
    }
}