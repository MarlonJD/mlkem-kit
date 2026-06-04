namespace MLKemNative;

public enum MLKemPrivateKeyExportPolicy
{
    ExportableSeedRepresentation,
    NonExportableHardwareIsolated,
    ProviderManaged,
}

public sealed record MLKemProviderMetadata(
    string ProviderId,
    string ParameterSet,
    bool IsPlatformNative,
    bool IsHardwareIsolated,
    bool IsFipsValidatedOrFormallyVerifiedClaimedByProvider,
    bool SupportsKeyGeneration,
    bool SupportsEncapsulation,
    bool SupportsDecapsulation,
    MLKemPrivateKeyExportPolicy PrivateKeyExportPolicy,
    string MinimumOSOrRuntime,
    string ImplementationLanguage,
    bool UsesAssemblyOrSimd,
    bool UsesCOrFfi,
    bool UsesPInvoke,
    string? NativeLibraryDependency,
    string LicenseAndSupplyChainStatus,
    bool FallbackAllowedInProduction,
    string OfficialSupportEvidence)
{
    public static MLKemProviderMetadata DotNetBuiltInMLKem768 { get; } = new(
        ProviderId: "dotnet-system-security-cryptography-mlkem768",
        ParameterSet: "ML-KEM-768",
        IsPlatformNative: true,
        IsHardwareIsolated: false,
        IsFipsValidatedOrFormallyVerifiedClaimedByProvider: false,
        SupportsKeyGeneration: true,
        SupportsEncapsulation: true,
        SupportsDecapsulation: true,
        PrivateKeyExportPolicy: MLKemPrivateKeyExportPolicy.ProviderManaged,
        MinimumOSOrRuntime: ".NET runtime with System.Security.Cryptography ML-KEM support and IsSupported=true",
        ImplementationLanguage: "C#/.NET official cryptography API",
        UsesAssemblyOrSimd: false,
        UsesCOrFfi: false,
        UsesPInvoke: false,
        NativeLibraryDependency: null,
        LicenseAndSupplyChainStatus: ".NET runtime official API",
        FallbackAllowedInProduction: false,
        OfficialSupportEvidence: ".NET 10 exposes ML-KEM APIs where runtime provider support reports IsSupported.");

    public static MLKemProviderMetadata ManagedCSharpMLKem768(bool fallbackAllowedInProduction = false) => new(
        ProviderId: "csharp-managed-mlkem768",
        ParameterSet: "ML-KEM-768",
        IsPlatformNative: false,
        IsHardwareIsolated: false,
        IsFipsValidatedOrFormallyVerifiedClaimedByProvider: false,
        SupportsKeyGeneration: true,
        SupportsEncapsulation: true,
        SupportsDecapsulation: true,
        PrivateKeyExportPolicy: MLKemPrivateKeyExportPolicy.ExportableSeedRepresentation,
        MinimumOSOrRuntime: ".NET 10 managed fallback",
        ImplementationLanguage: "C#",
        UsesAssemblyOrSimd: false,
        UsesCOrFfi: false,
        UsesPInvoke: false,
        NativeLibraryDependency: null,
        LicenseAndSupplyChainStatus: "mlkem-kit source, no vendored native dependency",
        FallbackAllowedInProduction: fallbackAllowedInProduction,
        OfficialSupportEvidence: "Managed fallback; not a platform-native .NET provider.");
}

public sealed record MLKemProviderAuditGates(
    bool Fips203CodeMapReviewed,
    bool PositiveVectorsPassed,
    bool NegativeVectorsPassed,
    bool SideChannelReviewPassed,
    bool ReleaseDeviceBenchmarksRecorded,
    bool ExternalCryptoReviewAccepted)
{
    public bool MaintainerRiskAcceptedForFallbackProduction { get; init; }

    public static MLKemProviderAuditGates Open { get; } = new(
        Fips203CodeMapReviewed: false,
        PositiveVectorsPassed: false,
        NegativeVectorsPassed: false,
        SideChannelReviewPassed: false,
        ReleaseDeviceBenchmarksRecorded: false,
        ExternalCryptoReviewAccepted: false);

    public static MLKemProviderAuditGates ClosedForFallbackProduction { get; } = new(
        Fips203CodeMapReviewed: true,
        PositiveVectorsPassed: true,
        NegativeVectorsPassed: true,
        SideChannelReviewPassed: true,
        ReleaseDeviceBenchmarksRecorded: true,
        ExternalCryptoReviewAccepted: true);

    public static MLKemProviderAuditGates RiskAcceptedForEmsiDmProductionFallback { get; } =
        Open with
        {
            PositiveVectorsPassed = true,
            NegativeVectorsPassed = true,
            ReleaseDeviceBenchmarksRecorded = true,
            MaintainerRiskAcceptedForFallbackProduction = true,
        };

    public bool AuditAcceptedForFallbackProduction =>
        Fips203CodeMapReviewed &&
        PositiveVectorsPassed &&
        NegativeVectorsPassed &&
        SideChannelReviewPassed &&
        ReleaseDeviceBenchmarksRecorded &&
        ExternalCryptoReviewAccepted;

    public bool FallbackProductionReady =>
        AuditAcceptedForFallbackProduction ||
        MaintainerRiskAcceptedForFallbackProduction;
}

public sealed record MLKemDotNetRuntimeCapabilities(
    bool BuiltInMLKemSupported,
    bool BuiltInProviderSupportsKeyGeneration,
    bool BuiltInProviderSupportsEncapsulation,
    bool BuiltInProviderSupportsDecapsulation,
    bool ManagedFallbackAvailable,
    string RuntimeDescription)
{
    public bool BuiltInProviderComplete =>
        BuiltInMLKemSupported &&
        BuiltInProviderSupportsKeyGeneration &&
        BuiltInProviderSupportsEncapsulation &&
        BuiltInProviderSupportsDecapsulation;
}

public sealed record MLKemProviderPolicy(
    MLKemProviderPolicy.ProviderEnvironment Environment,
    bool AllowsFallbackInProduction,
    MLKemProviderAuditGates AuditGates)
{
    public enum ProviderEnvironment
    {
        Production,
        NonProduction,
    }

    public static MLKemProviderPolicy Production(
        bool allowsFallbackInProduction = false,
        MLKemProviderAuditGates? auditGates = null) =>
        new(
            Environment: ProviderEnvironment.Production,
            AllowsFallbackInProduction: allowsFallbackInProduction,
            AuditGates: auditGates ?? MLKemProviderAuditGates.Open);

    public static MLKemProviderPolicy NonProduction() =>
        new(
            Environment: ProviderEnvironment.NonProduction,
            AllowsFallbackInProduction: false,
            AuditGates: MLKemProviderAuditGates.Open);

    public static MLKemProviderSelection SelectDotNetProvider(
        MLKemDotNetRuntimeCapabilities runtime,
        MLKemProviderPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(runtime);
        ArgumentNullException.ThrowIfNull(policy);

        if (runtime.BuiltInProviderComplete)
        {
            return MLKemProviderSelection.Selected(MLKemProviderMetadata.DotNetBuiltInMLKem768);
        }

        if (runtime.BuiltInMLKemSupported)
        {
            return MLKemProviderSelection.FailClosed(MLKemProviderFailureReason.BuiltInProviderIncomplete);
        }

        if (!runtime.ManagedFallbackAvailable)
        {
            return MLKemProviderSelection.FailClosed(MLKemProviderFailureReason.ProviderUnavailable);
        }

        return policy.Environment switch
        {
            ProviderEnvironment.NonProduction =>
                MLKemProviderSelection.Selected(MLKemProviderMetadata.ManagedCSharpMLKem768()),
            ProviderEnvironment.Production when !policy.AllowsFallbackInProduction =>
                MLKemProviderSelection.FailClosed(MLKemProviderFailureReason.FallbackDisallowedInProduction),
            ProviderEnvironment.Production when !policy.AuditGates.FallbackProductionReady =>
                MLKemProviderSelection.FailClosed(MLKemProviderFailureReason.FallbackAuditIncomplete),
            ProviderEnvironment.Production =>
                MLKemProviderSelection.Selected(
                    MLKemProviderMetadata.ManagedCSharpMLKem768(fallbackAllowedInProduction: true)),
            _ => MLKemProviderSelection.FailClosed(MLKemProviderFailureReason.ProviderUnavailable),
        };
    }
}

public enum MLKemProviderFailureReason
{
    ProviderUnavailable,
    FallbackDisallowedInProduction,
    FallbackAuditIncomplete,
    BuiltInProviderIncomplete,
}

public sealed record MLKemProviderSelection(
    MLKemProviderMetadata? Provider,
    MLKemProviderFailureReason? FailureReason)
{
    public static MLKemProviderSelection Selected(MLKemProviderMetadata provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        return new MLKemProviderSelection(Provider: provider, FailureReason: null);
    }

    public static MLKemProviderSelection FailClosed(MLKemProviderFailureReason reason) =>
        new(Provider: null, FailureReason: reason);
}
