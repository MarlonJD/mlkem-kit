import Foundation

/// Runtime platform names used by provider-selection policy tests and adapters.
public enum MLKEMApplePlatform: String, Sendable {
    case iOS
    case macOS
}

/// ML-KEM protocol mode requested by the caller.
public enum MLKEMProtocolMode: String, Sendable {
    case rawMLKEM768
    case xWingHPKE
}

/// Whether a provider stores private-key material in an exportable form.
public enum MLKEMPrivateKeyExportPolicy: String, Sendable {
    case exportableSeedRepresentation
    case nonExportableHardwareIsolated
    case providerManaged
}

/// Metadata required before a provider can be selected for production use.
public struct MLKEMProviderMetadata: Equatable, Sendable {
    public let providerId: String
    public let parameterSet: String
    public let isPlatformNative: Bool
    public let isHardwareIsolated: Bool
    public let isFipsValidatedOrFormallyVerifiedClaimedByProvider: Bool
    public let supportsKeyGeneration: Bool
    public let supportsEncapsulation: Bool
    public let supportsDecapsulation: Bool
    public let privateKeyExportPolicy: MLKEMPrivateKeyExportPolicy
    public let minimumOSOrRuntime: String
    public let implementationLanguage: String
    public let usesAssemblyOrSIMD: Bool
    public let usesCOrFFI: Bool
    public let nativeLibraryDependency: String?
    public let licenseAndSupplyChainStatus: String
    public let fallbackAllowedInProduction: Bool

    public static let appleCryptoKitMLKEM768 = MLKEMProviderMetadata(
        providerId: "apple-cryptokit-mlkem768",
        parameterSet: "ML-KEM-768",
        isPlatformNative: true,
        isHardwareIsolated: false,
        isFipsValidatedOrFormallyVerifiedClaimedByProvider: false,
        supportsKeyGeneration: true,
        supportsEncapsulation: true,
        supportsDecapsulation: true,
        privateKeyExportPolicy: .providerManaged,
        minimumOSOrRuntime: "iOS 26 / macOS 26 with CryptoKit MLKEM768 SDK symbols",
        implementationLanguage: "Swift/CryptoKit",
        usesAssemblyOrSIMD: false,
        usesCOrFFI: false,
        nativeLibraryDependency: nil,
        licenseAndSupplyChainStatus: "Apple platform SDK",
        fallbackAllowedInProduction: false
    )

    public static let appleCryptoKitXWingMLKEM768X25519 = MLKEMProviderMetadata(
        providerId: "apple-cryptokit-xwing-mlkem768-x25519",
        parameterSet: "XWingMLKEM768X25519",
        isPlatformNative: true,
        isHardwareIsolated: false,
        isFipsValidatedOrFormallyVerifiedClaimedByProvider: false,
        supportsKeyGeneration: true,
        supportsEncapsulation: true,
        supportsDecapsulation: true,
        privateKeyExportPolicy: .providerManaged,
        minimumOSOrRuntime: "iOS 26 / macOS 26 with CryptoKit XWingMLKEM768X25519 SDK symbols",
        implementationLanguage: "Swift/CryptoKit HPKE",
        usesAssemblyOrSIMD: false,
        usesCOrFFI: false,
        nativeLibraryDependency: nil,
        licenseAndSupplyChainStatus: "Apple platform SDK",
        fallbackAllowedInProduction: false
    )

    public static let appleSecureEnclaveMLKEM768 = MLKEMProviderMetadata(
        providerId: "apple-secure-enclave-mlkem768",
        parameterSet: "ML-KEM-768",
        isPlatformNative: true,
        isHardwareIsolated: true,
        isFipsValidatedOrFormallyVerifiedClaimedByProvider: false,
        supportsKeyGeneration: true,
        supportsEncapsulation: true,
        supportsDecapsulation: true,
        privateKeyExportPolicy: .nonExportableHardwareIsolated,
        minimumOSOrRuntime: "iOS 26 / macOS 26 with lifecycle-compatible Secure Enclave ML-KEM",
        implementationLanguage: "Swift/CryptoKit/Secure Enclave",
        usesAssemblyOrSIMD: false,
        usesCOrFFI: false,
        nativeLibraryDependency: nil,
        licenseAndSupplyChainStatus: "Apple platform SDK",
        fallbackAllowedInProduction: false
    )

    public static func pureSwiftMLKEM768(fallbackAllowedInProduction: Bool = false) -> MLKEMProviderMetadata {
        MLKEMProviderMetadata(
            providerId: "swift-pure-mlkem768",
            parameterSet: "ML-KEM-768",
            isPlatformNative: false,
            isHardwareIsolated: false,
            isFipsValidatedOrFormallyVerifiedClaimedByProvider: false,
            supportsKeyGeneration: true,
            supportsEncapsulation: true,
            supportsDecapsulation: true,
            privateKeyExportPolicy: .exportableSeedRepresentation,
            minimumOSOrRuntime: "iOS 13 / macOS 10.15 Swift fallback",
            implementationLanguage: "Swift",
            usesAssemblyOrSIMD: false,
            usesCOrFFI: false,
            nativeLibraryDependency: nil,
            licenseAndSupplyChainStatus: "mlkem-kit source, no vendored native dependency",
            fallbackAllowedInProduction: fallbackAllowedInProduction
        )
    }
}

/// Audit gates that must close before a pure Swift fallback is production-selectable.
public struct MLKEMProviderAuditGates: Equatable, Sendable {
    public let fips203CodeMapReviewed: Bool
    public let positiveVectorsPassed: Bool
    public let negativeVectorsPassed: Bool
    public let sideChannelReviewPassed: Bool
    public let releaseDeviceBenchmarksRecorded: Bool
    public let externalCryptoReviewAccepted: Bool

    public init(fips203CodeMapReviewed: Bool,
                positiveVectorsPassed: Bool,
                negativeVectorsPassed: Bool,
                sideChannelReviewPassed: Bool,
                releaseDeviceBenchmarksRecorded: Bool,
                externalCryptoReviewAccepted: Bool) {
        self.fips203CodeMapReviewed = fips203CodeMapReviewed
        self.positiveVectorsPassed = positiveVectorsPassed
        self.negativeVectorsPassed = negativeVectorsPassed
        self.sideChannelReviewPassed = sideChannelReviewPassed
        self.releaseDeviceBenchmarksRecorded = releaseDeviceBenchmarksRecorded
        self.externalCryptoReviewAccepted = externalCryptoReviewAccepted
    }

    public static let open = MLKEMProviderAuditGates(
        fips203CodeMapReviewed: false,
        positiveVectorsPassed: false,
        negativeVectorsPassed: false,
        sideChannelReviewPassed: false,
        releaseDeviceBenchmarksRecorded: false,
        externalCryptoReviewAccepted: false
    )

    public static let closedForFallbackProduction = MLKEMProviderAuditGates(
        fips203CodeMapReviewed: true,
        positiveVectorsPassed: true,
        negativeVectorsPassed: true,
        sideChannelReviewPassed: true,
        releaseDeviceBenchmarksRecorded: true,
        externalCryptoReviewAccepted: true
    )

    public var fallbackProductionReady: Bool {
        fips203CodeMapReviewed &&
            positiveVectorsPassed &&
            negativeVectorsPassed &&
            sideChannelReviewPassed &&
            releaseDeviceBenchmarksRecorded &&
            externalCryptoReviewAccepted
    }
}

/// App/runtime facts that can be simulated in tests and supplied by adapters.
public struct MLKEMAppleRuntimeCapabilities: Equatable, Sendable {
    public let platform: MLKEMApplePlatform
    public let osMajorVersion: Int
    public let sdkExposesCryptoKitMLKEM768: Bool
    public let sdkExposesCryptoKitXWing: Bool
    public let secureEnclaveMLKEMAvailable: Bool
    public let secureEnclaveKeyLifecycleCompatible: Bool
    public let pureSwiftFallbackAvailable: Bool

    public init(platform: MLKEMApplePlatform,
                osMajorVersion: Int,
                sdkExposesCryptoKitMLKEM768: Bool,
                sdkExposesCryptoKitXWing: Bool,
                secureEnclaveMLKEMAvailable: Bool,
                secureEnclaveKeyLifecycleCompatible: Bool,
                pureSwiftFallbackAvailable: Bool) {
        self.platform = platform
        self.osMajorVersion = osMajorVersion
        self.sdkExposesCryptoKitMLKEM768 = sdkExposesCryptoKitMLKEM768
        self.sdkExposesCryptoKitXWing = sdkExposesCryptoKitXWing
        self.secureEnclaveMLKEMAvailable = secureEnclaveMLKEMAvailable
        self.secureEnclaveKeyLifecycleCompatible = secureEnclaveKeyLifecycleCompatible
        self.pureSwiftFallbackAvailable = pureSwiftFallbackAvailable
    }

    public var isOS26OrNewer: Bool {
        osMajorVersion >= 26
    }
}

/// Selection policy for production and non-production provider decisions.
public struct MLKEMProviderPolicy: Equatable, Sendable {
    public enum Environment: String, Sendable {
        case production
        case nonProduction
    }

    public let environment: Environment
    public let protocolMode: MLKEMProtocolMode
    public let prefersHardwareIsolation: Bool
    public let allowsFallbackInProduction: Bool
    public let auditGates: MLKEMProviderAuditGates

    public init(environment: Environment,
                protocolMode: MLKEMProtocolMode,
                prefersHardwareIsolation: Bool = false,
                allowsFallbackInProduction: Bool = false,
                auditGates: MLKEMProviderAuditGates = .open) {
        self.environment = environment
        self.protocolMode = protocolMode
        self.prefersHardwareIsolation = prefersHardwareIsolation
        self.allowsFallbackInProduction = allowsFallbackInProduction
        self.auditGates = auditGates
    }

    public static func production(protocolMode: MLKEMProtocolMode,
                                  prefersHardwareIsolation: Bool = false,
                                  allowsFallbackInProduction: Bool = false,
                                  auditGates: MLKEMProviderAuditGates = .open) -> MLKEMProviderPolicy {
        MLKEMProviderPolicy(
            environment: .production,
            protocolMode: protocolMode,
            prefersHardwareIsolation: prefersHardwareIsolation,
            allowsFallbackInProduction: allowsFallbackInProduction,
            auditGates: auditGates
        )
    }

    public static func nonProduction(protocolMode: MLKEMProtocolMode,
                                     prefersHardwareIsolation: Bool = false) -> MLKEMProviderPolicy {
        MLKEMProviderPolicy(
            environment: .nonProduction,
            protocolMode: protocolMode,
            prefersHardwareIsolation: prefersHardwareIsolation,
            allowsFallbackInProduction: false,
            auditGates: .open
        )
    }

    public static func selectAppleProvider(runtime: MLKEMAppleRuntimeCapabilities,
                                           policy: MLKEMProviderPolicy) -> MLKEMProviderSelection {
        switch policy.protocolMode {
        case .xWingHPKE:
            if runtime.isOS26OrNewer, runtime.sdkExposesCryptoKitXWing {
                return .selected(.appleCryptoKitXWingMLKEM768X25519)
            }
            return .failClosed(.providerProtocolMismatch)
        case .rawMLKEM768:
            if policy.prefersHardwareIsolation,
               runtime.isOS26OrNewer,
               runtime.secureEnclaveMLKEMAvailable,
               runtime.secureEnclaveKeyLifecycleCompatible {
                return .selected(.appleSecureEnclaveMLKEM768)
            }

            if runtime.isOS26OrNewer, runtime.sdkExposesCryptoKitMLKEM768 {
                return .selected(.appleCryptoKitMLKEM768)
            }
        }

        guard runtime.pureSwiftFallbackAvailable else {
            return .failClosed(.providerUnavailable)
        }

        switch policy.environment {
        case .nonProduction:
            return .selected(.pureSwiftMLKEM768())
        case .production:
            guard policy.allowsFallbackInProduction else {
                return .failClosed(.fallbackDisallowedInProduction)
            }
            guard policy.auditGates.fallbackProductionReady else {
                return .failClosed(.fallbackAuditIncomplete)
            }
            return .selected(.pureSwiftMLKEM768(fallbackAllowedInProduction: true))
        }
    }
}

/// Fail-closed reasons surfaced to app adapters and release checks.
public enum MLKEMProviderFailureReason: String, Sendable {
    case providerUnavailable
    case providerProtocolMismatch
    case fallbackDisallowedInProduction
    case fallbackAuditIncomplete
}

/// Result of deterministic provider selection.
public enum MLKEMProviderSelection: Equatable, Sendable {
    case selected(MLKEMProviderMetadata)
    case failClosed(MLKEMProviderFailureReason)

    public var provider: MLKEMProviderMetadata? {
        if case let .selected(provider) = self {
            return provider
        }
        return nil
    }

    public var failureReason: MLKEMProviderFailureReason? {
        if case let .failClosed(reason) = self {
            return reason
        }
        return nil
    }
}
