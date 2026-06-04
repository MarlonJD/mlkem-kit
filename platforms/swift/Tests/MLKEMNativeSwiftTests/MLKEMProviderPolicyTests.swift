import Testing
@testable import MLKEMNativeSwift

@Suite("ML-KEM Apple provider policy")
struct MLKEMProviderPolicyTests {
    @Test("iOS 26 raw ML-KEM selects CryptoKit only when SDK symbols are available")
    func ios26RawProviderSelectsCryptoKitWhenSymbolsAvailable() {
        let runtime = MLKEMAppleRuntimeCapabilities(
            platform: .iOS,
            osMajorVersion: 26,
            sdkExposesCryptoKitMLKEM768: true,
            sdkExposesCryptoKitXWing: false,
            secureEnclaveMLKEMAvailable: false,
            secureEnclaveKeyLifecycleCompatible: false,
            pureSwiftFallbackAvailable: true
        )

        let selection = MLKEMProviderPolicy.selectAppleProvider(
            runtime: runtime,
            policy: .production(protocolMode: .rawMLKEM768)
        )

        #expect(selection.provider?.providerId == "apple-cryptokit-mlkem768")
        #expect(selection.provider?.isPlatformNative == true)
        #expect(selection.provider?.usesCOrFFI == false)
    }

    @Test("macOS 26 X-Wing HPKE selects CryptoKit X-Wing only for hybrid mode")
    func macOS26XWingSelectsCryptoKitOnlyForHybridMode() {
        let runtime = MLKEMAppleRuntimeCapabilities(
            platform: .macOS,
            osMajorVersion: 26,
            sdkExposesCryptoKitMLKEM768: false,
            sdkExposesCryptoKitXWing: true,
            secureEnclaveMLKEMAvailable: false,
            secureEnclaveKeyLifecycleCompatible: false,
            pureSwiftFallbackAvailable: true
        )

        let selection = MLKEMProviderPolicy.selectAppleProvider(
            runtime: runtime,
            policy: .production(protocolMode: .xWingHPKE)
        )

        #expect(selection.provider?.providerId == "apple-cryptokit-xwing-mlkem768-x25519")
        #expect(selection.provider?.parameterSet == "XWingMLKEM768X25519")
    }

    @Test("X-Wing HPKE never selects raw Secure Enclave ML-KEM")
    func xWingDoesNotSelectRawSecureEnclaveProvider() {
        let runtime = MLKEMAppleRuntimeCapabilities(
            platform: .iOS,
            osMajorVersion: 26,
            sdkExposesCryptoKitMLKEM768: true,
            sdkExposesCryptoKitXWing: false,
            secureEnclaveMLKEMAvailable: true,
            secureEnclaveKeyLifecycleCompatible: true,
            pureSwiftFallbackAvailable: true
        )

        let selection = MLKEMProviderPolicy.selectAppleProvider(
            runtime: runtime,
            policy: .production(
                protocolMode: .xWingHPKE,
                prefersHardwareIsolation: true,
                allowsFallbackInProduction: true,
                auditGates: .closedForFallbackProduction
            )
        )

        #expect(selection.provider == nil)
        #expect(selection.failureReason == .providerProtocolMismatch)
    }

    @Test("X-Wing HPKE never falls back to plain Swift ML-KEM")
    func xWingDoesNotUsePlainSwiftFallback() {
        let runtime = MLKEMAppleRuntimeCapabilities(
            platform: .macOS,
            osMajorVersion: 25,
            sdkExposesCryptoKitMLKEM768: false,
            sdkExposesCryptoKitXWing: false,
            secureEnclaveMLKEMAvailable: false,
            secureEnclaveKeyLifecycleCompatible: false,
            pureSwiftFallbackAvailable: true
        )

        let selection = MLKEMProviderPolicy.selectAppleProvider(
            runtime: runtime,
            policy: .production(
                protocolMode: .xWingHPKE,
                allowsFallbackInProduction: true,
                auditGates: .closedForFallbackProduction
            )
        )

        #expect(selection.provider == nil)
        #expect(selection.failureReason == .providerProtocolMismatch)
    }

    @Test("Secure Enclave provider is not selected unless key lifecycle is compatible")
    func secureEnclaveRequiresLifecycleCompatibility() {
        let runtime = MLKEMAppleRuntimeCapabilities(
            platform: .iOS,
            osMajorVersion: 26,
            sdkExposesCryptoKitMLKEM768: true,
            sdkExposesCryptoKitXWing: false,
            secureEnclaveMLKEMAvailable: true,
            secureEnclaveKeyLifecycleCompatible: false,
            pureSwiftFallbackAvailable: true
        )

        let selection = MLKEMProviderPolicy.selectAppleProvider(
            runtime: runtime,
            policy: .production(protocolMode: .rawMLKEM768, prefersHardwareIsolation: true)
        )

        #expect(selection.provider?.providerId == "apple-cryptokit-mlkem768")
        #expect(selection.provider?.isHardwareIsolated == false)
    }

    @Test("Apple production below OS 26 fails closed when fallback audit gates are incomplete")
    func productionBelow26FailsClosedWhenFallbackAuditIncomplete() {
        let runtime = MLKEMAppleRuntimeCapabilities(
            platform: .iOS,
            osMajorVersion: 25,
            sdkExposesCryptoKitMLKEM768: false,
            sdkExposesCryptoKitXWing: false,
            secureEnclaveMLKEMAvailable: false,
            secureEnclaveKeyLifecycleCompatible: false,
            pureSwiftFallbackAvailable: true
        )

        let selection = MLKEMProviderPolicy.selectAppleProvider(
            runtime: runtime,
            policy: .production(protocolMode: .rawMLKEM768, allowsFallbackInProduction: true)
        )

        #expect(selection.failureReason == .fallbackAuditIncomplete)
    }

    @Test("Apple production fallback fails closed when one audit gate remains open")
    func productionFallbackFailsClosedWhenSingleAuditGateOpen() {
        let runtime = MLKEMAppleRuntimeCapabilities(
            platform: .macOS,
            osMajorVersion: 25,
            sdkExposesCryptoKitMLKEM768: false,
            sdkExposesCryptoKitXWing: false,
            secureEnclaveMLKEMAvailable: false,
            secureEnclaveKeyLifecycleCompatible: false,
            pureSwiftFallbackAvailable: true
        )

        let gates = MLKEMProviderAuditGates(
            fips203CodeMapReviewed: true,
            positiveVectorsPassed: true,
            negativeVectorsPassed: true,
            sideChannelReviewPassed: true,
            releaseDeviceBenchmarksRecorded: false,
            externalCryptoReviewAccepted: true
        )

        let selection = MLKEMProviderPolicy.selectAppleProvider(
            runtime: runtime,
            policy: .production(
                protocolMode: .rawMLKEM768,
                allowsFallbackInProduction: true,
                auditGates: gates
            )
        )

        #expect(selection.provider == nil)
        #expect(selection.failureReason == .fallbackAuditIncomplete)
    }

    @Test("Apple production fallback is selected only after all audit gates pass and policy allows it")
    func productionFallbackRequiresClosedAuditGatesAndPolicyAllowance() {
        let runtime = MLKEMAppleRuntimeCapabilities(
            platform: .macOS,
            osMajorVersion: 25,
            sdkExposesCryptoKitMLKEM768: false,
            sdkExposesCryptoKitXWing: false,
            secureEnclaveMLKEMAvailable: false,
            secureEnclaveKeyLifecycleCompatible: false,
            pureSwiftFallbackAvailable: true
        )

        let selection = MLKEMProviderPolicy.selectAppleProvider(
            runtime: runtime,
            policy: .production(
                protocolMode: .rawMLKEM768,
                allowsFallbackInProduction: true,
                auditGates: .closedForFallbackProduction
            )
        )

        #expect(selection.provider?.providerId == "swift-pure-mlkem768")
        #expect(selection.provider?.implementationLanguage == "Swift")
        #expect(selection.provider?.fallbackAllowedInProduction == true)
    }

    @Test("Swift fallback metadata remains language-native and blocks native dependencies")
    func swiftFallbackMetadataBlocksNativeDependencies() {
        let provider = MLKEMProviderMetadata.pureSwiftMLKEM768()

        #expect(provider.usesCOrFFI == false)
        #expect(provider.nativeLibraryDependency == nil)
        #expect(provider.usesAssemblyOrSIMD == false)
        #expect(provider.fallbackAllowedInProduction == false)
        #expect(provider.privateKeyExportPolicy == .exportableSeedRepresentation)
    }
}
