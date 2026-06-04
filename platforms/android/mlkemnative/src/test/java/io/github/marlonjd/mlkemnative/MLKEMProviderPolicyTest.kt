package io.github.marlonjd.mlkemnative

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class MLKEMProviderPolicyTest {
    @Test
    fun officialAndroidProviderIsSelectedOnlyWhenAppFacingKemOperationsExist() {
        val runtime = MLKEMAndroidRuntimeCapabilities(
            officialAppFacingMLKEMAvailable = true,
            officialProviderSupportsKeyGeneration = true,
            officialProviderSupportsEncapsulation = true,
            officialProviderSupportsDecapsulation = true,
            keyStoreHardwareBackedStorageAvailable = true,
            pureKotlinFallbackAvailable = true,
        )

        val selection = MLKEMProviderPolicy.selectAndroidProvider(
            runtime = runtime,
            policy = MLKEMProviderPolicy.production(),
        )

        assertEquals("android-official-mlkem768", selection.provider?.providerId)
        assertTrue(selection.provider!!.isPlatformNative)
        assertFalse(selection.provider!!.usesCOrFFI)
    }

    @Test
    fun keystoreStorageAloneIsNotTreatedAsMlKemOperationSupport() {
        val runtime = MLKEMAndroidRuntimeCapabilities(
            officialAppFacingMLKEMAvailable = false,
            officialProviderSupportsKeyGeneration = false,
            officialProviderSupportsEncapsulation = false,
            officialProviderSupportsDecapsulation = false,
            keyStoreHardwareBackedStorageAvailable = true,
            pureKotlinFallbackAvailable = false,
        )

        val selection = MLKEMProviderPolicy.selectAndroidProvider(
            runtime = runtime,
            policy = MLKEMProviderPolicy.production(),
        )

        assertNull(selection.provider)
        assertEquals(MLKEMProviderFailureReason.PROVIDER_UNAVAILABLE, selection.failureReason)
    }

    @Test
    fun officialAndroidProviderMustExposeEveryKemOperation() {
        val runtime = MLKEMAndroidRuntimeCapabilities(
            officialAppFacingMLKEMAvailable = true,
            officialProviderSupportsKeyGeneration = true,
            officialProviderSupportsEncapsulation = true,
            officialProviderSupportsDecapsulation = false,
            keyStoreHardwareBackedStorageAvailable = true,
            pureKotlinFallbackAvailable = true,
        )

        val selection = MLKEMProviderPolicy.selectAndroidProvider(
            runtime = runtime,
            policy = MLKEMProviderPolicy.production(),
        )

        assertNull(selection.provider)
        assertEquals(MLKEMProviderFailureReason.OFFICIAL_PROVIDER_INCOMPLETE, selection.failureReason)
    }

    @Test
    fun productionFallbackFailsClosedWhenAuditGatesAreIncomplete() {
        val runtime = MLKEMAndroidRuntimeCapabilities(
            officialAppFacingMLKEMAvailable = false,
            officialProviderSupportsKeyGeneration = false,
            officialProviderSupportsEncapsulation = false,
            officialProviderSupportsDecapsulation = false,
            keyStoreHardwareBackedStorageAvailable = true,
            pureKotlinFallbackAvailable = true,
        )

        val selection = MLKEMProviderPolicy.selectAndroidProvider(
            runtime = runtime,
            policy = MLKEMProviderPolicy.production(allowsFallbackInProduction = true),
        )

        assertNull(selection.provider)
        assertEquals(MLKEMProviderFailureReason.FALLBACK_AUDIT_INCOMPLETE, selection.failureReason)
    }

    @Test
    fun productionFallbackRequiresExplicitPolicyAllowanceEvenWithClosedAuditGates() {
        val runtime = MLKEMAndroidRuntimeCapabilities(
            officialAppFacingMLKEMAvailable = false,
            officialProviderSupportsKeyGeneration = false,
            officialProviderSupportsEncapsulation = false,
            officialProviderSupportsDecapsulation = false,
            keyStoreHardwareBackedStorageAvailable = false,
            pureKotlinFallbackAvailable = true,
        )

        val selection = MLKEMProviderPolicy.selectAndroidProvider(
            runtime = runtime,
            policy = MLKEMProviderPolicy.production(
                auditGates = MLKEMProviderAuditGates.CLOSED_FOR_FALLBACK_PRODUCTION,
            ),
        )

        assertNull(selection.provider)
        assertEquals(MLKEMProviderFailureReason.FALLBACK_DISALLOWED_IN_PRODUCTION, selection.failureReason)
    }

    @Test
    fun productionFallbackFailsClosedWhenSingleAuditGateIsOpen() {
        val runtime = MLKEMAndroidRuntimeCapabilities(
            officialAppFacingMLKEMAvailable = false,
            officialProviderSupportsKeyGeneration = false,
            officialProviderSupportsEncapsulation = false,
            officialProviderSupportsDecapsulation = false,
            keyStoreHardwareBackedStorageAvailable = false,
            pureKotlinFallbackAvailable = true,
        )
        val gates = MLKEMProviderAuditGates(
            fips203CodeMapReviewed = true,
            positiveVectorsPassed = true,
            negativeVectorsPassed = true,
            sideChannelReviewPassed = true,
            releaseDeviceBenchmarksRecorded = false,
            externalCryptoReviewAccepted = true,
        )

        val selection = MLKEMProviderPolicy.selectAndroidProvider(
            runtime = runtime,
            policy = MLKEMProviderPolicy.production(
                allowsFallbackInProduction = true,
                auditGates = gates,
            ),
        )

        assertNull(selection.provider)
        assertEquals(MLKEMProviderFailureReason.FALLBACK_AUDIT_INCOMPLETE, selection.failureReason)
    }

    @Test
    fun productionFallbackRequiresBothPolicyAllowanceAndClosedAuditGates() {
        val runtime = MLKEMAndroidRuntimeCapabilities(
            officialAppFacingMLKEMAvailable = false,
            officialProviderSupportsKeyGeneration = false,
            officialProviderSupportsEncapsulation = false,
            officialProviderSupportsDecapsulation = false,
            keyStoreHardwareBackedStorageAvailable = false,
            pureKotlinFallbackAvailable = true,
        )
        val cases = listOf(
            MLKEMProviderPolicy.production() to
                MLKEMProviderFailureReason.FALLBACK_DISALLOWED_IN_PRODUCTION,
            MLKEMProviderPolicy.production(allowsFallbackInProduction = true) to
                MLKEMProviderFailureReason.FALLBACK_AUDIT_INCOMPLETE,
            MLKEMProviderPolicy.production(
                auditGates = MLKEMProviderAuditGates.CLOSED_FOR_FALLBACK_PRODUCTION,
            ) to MLKEMProviderFailureReason.FALLBACK_DISALLOWED_IN_PRODUCTION,
        )

        cases.forEach { (policy, expectedFailure) ->
            val selection = MLKEMProviderPolicy.selectAndroidProvider(
                runtime = runtime,
                policy = policy,
            )

            assertNull(selection.provider)
            assertEquals(expectedFailure, selection.failureReason)
        }
    }

    @Test
    fun auditedPureKotlinFallbackRequiresPolicyAllowanceInProduction() {
        val runtime = MLKEMAndroidRuntimeCapabilities(
            officialAppFacingMLKEMAvailable = false,
            officialProviderSupportsKeyGeneration = false,
            officialProviderSupportsEncapsulation = false,
            officialProviderSupportsDecapsulation = false,
            keyStoreHardwareBackedStorageAvailable = false,
            pureKotlinFallbackAvailable = true,
        )

        val selection = MLKEMProviderPolicy.selectAndroidProvider(
            runtime = runtime,
            policy = MLKEMProviderPolicy.production(
                allowsFallbackInProduction = true,
                auditGates = MLKEMProviderAuditGates.CLOSED_FOR_FALLBACK_PRODUCTION,
            ),
        )

        assertEquals("kotlin-pure-mlkem768", selection.provider?.providerId)
        assertEquals("Kotlin", selection.provider?.implementationLanguage)
        assertTrue(selection.provider!!.fallbackAllowedInProduction)
    }

    @Test
    fun pureKotlinMetadataBlocksNativeFallbacks() {
        val provider = MLKEMProviderMetadata.pureKotlinMLKEM768()

        assertFalse(provider.usesCOrFFI)
        assertNull(provider.nativeLibraryDependency)
        assertFalse(provider.usesAssemblyOrSIMD)
        assertFalse(provider.fallbackAllowedInProduction)
        assertEquals(MLKEMPrivateKeyExportPolicy.EXPORTABLE_SEED_REPRESENTATION, provider.privateKeyExportPolicy)
    }
}
