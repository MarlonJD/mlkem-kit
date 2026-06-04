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
