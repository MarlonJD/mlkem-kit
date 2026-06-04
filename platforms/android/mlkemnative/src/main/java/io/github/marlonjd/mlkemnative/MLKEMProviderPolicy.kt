package io.github.marlonjd.mlkemnative

enum class MLKEMPrivateKeyExportPolicy {
    EXPORTABLE_SEED_REPRESENTATION,
    NON_EXPORTABLE_HARDWARE_ISOLATED,
    PROVIDER_MANAGED,
}

data class MLKEMProviderMetadata(
    val providerId: String,
    val parameterSet: String,
    val isPlatformNative: Boolean,
    val isHardwareIsolated: Boolean,
    val isFipsValidatedOrFormallyVerifiedClaimedByProvider: Boolean,
    val supportsKeyGeneration: Boolean,
    val supportsEncapsulation: Boolean,
    val supportsDecapsulation: Boolean,
    val privateKeyExportPolicy: MLKEMPrivateKeyExportPolicy,
    val minimumOSOrRuntime: String,
    val implementationLanguage: String,
    val usesAssemblyOrSIMD: Boolean,
    val usesCOrFFI: Boolean,
    val nativeLibraryDependency: String?,
    val licenseAndSupplyChainStatus: String,
    val fallbackAllowedInProduction: Boolean,
    val officialSupportEvidence: String,
) {
    companion object {
        val androidOfficialMLKEM768 = MLKEMProviderMetadata(
            providerId = "android-official-mlkem768",
            parameterSet = "ML-KEM-768",
            isPlatformNative = true,
            isHardwareIsolated = false,
            isFipsValidatedOrFormallyVerifiedClaimedByProvider = false,
            supportsKeyGeneration = true,
            supportsEncapsulation = true,
            supportsDecapsulation = true,
            privateKeyExportPolicy = MLKEMPrivateKeyExportPolicy.PROVIDER_MANAGED,
            minimumOSOrRuntime = "Future Android API with app-facing ML-KEM KEM operations",
            implementationLanguage = "Kotlin/Android platform API",
            usesAssemblyOrSIMD = false,
            usesCOrFFI = false,
            nativeLibraryDependency = null,
            licenseAndSupplyChainStatus = "Android SDK official API",
            fallbackAllowedInProduction = false,
            officialSupportEvidence = "No app-facing Android ML-KEM KEM operation API found in official docs on 2026-06-04.",
        )

        fun pureKotlinMLKEM768(fallbackAllowedInProduction: Boolean = false): MLKEMProviderMetadata =
            MLKEMProviderMetadata(
                providerId = "kotlin-pure-mlkem768",
                parameterSet = "ML-KEM-768",
                isPlatformNative = false,
                isHardwareIsolated = false,
                isFipsValidatedOrFormallyVerifiedClaimedByProvider = false,
                supportsKeyGeneration = true,
                supportsEncapsulation = true,
                supportsDecapsulation = true,
                privateKeyExportPolicy = MLKEMPrivateKeyExportPolicy.EXPORTABLE_SEED_REPRESENTATION,
                minimumOSOrRuntime = "Android API 23 / JVM 17 pure Kotlin fallback",
                implementationLanguage = "Kotlin",
                usesAssemblyOrSIMD = false,
                usesCOrFFI = false,
                nativeLibraryDependency = null,
                licenseAndSupplyChainStatus = "mlkem-kit source, no vendored native dependency",
                fallbackAllowedInProduction = fallbackAllowedInProduction,
                officialSupportEvidence = "Language-native fallback; not an Android platform KEM provider.",
            )
    }
}

data class MLKEMProviderAuditGates(
    val fips203CodeMapReviewed: Boolean,
    val positiveVectorsPassed: Boolean,
    val negativeVectorsPassed: Boolean,
    val sideChannelReviewPassed: Boolean,
    val releaseDeviceBenchmarksRecorded: Boolean,
    val externalCryptoReviewAccepted: Boolean,
) {
    val fallbackProductionReady: Boolean
        get() = fips203CodeMapReviewed &&
            positiveVectorsPassed &&
            negativeVectorsPassed &&
            sideChannelReviewPassed &&
            releaseDeviceBenchmarksRecorded &&
            externalCryptoReviewAccepted

    companion object {
        val OPEN = MLKEMProviderAuditGates(
            fips203CodeMapReviewed = false,
            positiveVectorsPassed = false,
            negativeVectorsPassed = false,
            sideChannelReviewPassed = false,
            releaseDeviceBenchmarksRecorded = false,
            externalCryptoReviewAccepted = false,
        )

        val CLOSED_FOR_FALLBACK_PRODUCTION = MLKEMProviderAuditGates(
            fips203CodeMapReviewed = true,
            positiveVectorsPassed = true,
            negativeVectorsPassed = true,
            sideChannelReviewPassed = true,
            releaseDeviceBenchmarksRecorded = true,
            externalCryptoReviewAccepted = true,
        )
    }
}

data class MLKEMAndroidRuntimeCapabilities(
    val officialAppFacingMLKEMAvailable: Boolean,
    val officialProviderSupportsKeyGeneration: Boolean,
    val officialProviderSupportsEncapsulation: Boolean,
    val officialProviderSupportsDecapsulation: Boolean,
    val keyStoreHardwareBackedStorageAvailable: Boolean,
    val pureKotlinFallbackAvailable: Boolean,
) {
    val officialProviderComplete: Boolean
        get() = officialAppFacingMLKEMAvailable &&
            officialProviderSupportsKeyGeneration &&
            officialProviderSupportsEncapsulation &&
            officialProviderSupportsDecapsulation
}

data class MLKEMProviderPolicy(
    val environment: Environment,
    val allowsFallbackInProduction: Boolean = false,
    val auditGates: MLKEMProviderAuditGates = MLKEMProviderAuditGates.OPEN,
) {
    enum class Environment {
        PRODUCTION,
        NON_PRODUCTION,
    }

    companion object {
        fun production(
            allowsFallbackInProduction: Boolean = false,
            auditGates: MLKEMProviderAuditGates = MLKEMProviderAuditGates.OPEN,
        ): MLKEMProviderPolicy =
            MLKEMProviderPolicy(
                environment = Environment.PRODUCTION,
                allowsFallbackInProduction = allowsFallbackInProduction,
                auditGates = auditGates,
            )

        fun nonProduction(): MLKEMProviderPolicy =
            MLKEMProviderPolicy(environment = Environment.NON_PRODUCTION)

        fun selectAndroidProvider(
            runtime: MLKEMAndroidRuntimeCapabilities,
            policy: MLKEMProviderPolicy,
        ): MLKEMProviderSelection {
            if (runtime.officialProviderComplete) {
                return MLKEMProviderSelection.selected(MLKEMProviderMetadata.androidOfficialMLKEM768)
            }

            if (runtime.officialAppFacingMLKEMAvailable) {
                return MLKEMProviderSelection.failClosed(MLKEMProviderFailureReason.OFFICIAL_PROVIDER_INCOMPLETE)
            }

            if (!runtime.pureKotlinFallbackAvailable) {
                return MLKEMProviderSelection.failClosed(MLKEMProviderFailureReason.PROVIDER_UNAVAILABLE)
            }

            return when (policy.environment) {
                Environment.NON_PRODUCTION ->
                    MLKEMProviderSelection.selected(MLKEMProviderMetadata.pureKotlinMLKEM768())

                Environment.PRODUCTION -> {
                    if (!policy.allowsFallbackInProduction) {
                        MLKEMProviderSelection.failClosed(
                            MLKEMProviderFailureReason.FALLBACK_DISALLOWED_IN_PRODUCTION,
                        )
                    } else if (!policy.auditGates.fallbackProductionReady) {
                        MLKEMProviderSelection.failClosed(
                            MLKEMProviderFailureReason.FALLBACK_AUDIT_INCOMPLETE,
                        )
                    } else {
                        MLKEMProviderSelection.selected(
                            MLKEMProviderMetadata.pureKotlinMLKEM768(fallbackAllowedInProduction = true),
                        )
                    }
                }
            }
        }
    }
}

enum class MLKEMProviderFailureReason {
    PROVIDER_UNAVAILABLE,
    FALLBACK_DISALLOWED_IN_PRODUCTION,
    FALLBACK_AUDIT_INCOMPLETE,
    OFFICIAL_PROVIDER_INCOMPLETE,
}

class MLKEMProviderSelection private constructor(
    val provider: MLKEMProviderMetadata?,
    val failureReason: MLKEMProviderFailureReason?,
) {
    companion object {
        fun selected(provider: MLKEMProviderMetadata): MLKEMProviderSelection =
            MLKEMProviderSelection(provider = provider, failureReason = null)

        fun failClosed(reason: MLKEMProviderFailureReason): MLKEMProviderSelection =
            MLKEMProviderSelection(provider = null, failureReason = reason)
    }
}
