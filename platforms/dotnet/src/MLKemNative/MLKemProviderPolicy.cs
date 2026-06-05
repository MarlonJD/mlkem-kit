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
    bool FallbackSelectedForExplicitRiskException,
    bool ExternalCryptoApprovedForProduction,
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
        FallbackSelectedForExplicitRiskException: false,
        ExternalCryptoApprovedForProduction: false,
        OfficialSupportEvidence: ".NET 10 exposes ML-KEM APIs where runtime provider support reports IsSupported.");

    public static MLKemProviderMetadata ManagedCSharpMLKem768(
        bool fallbackAllowedInProduction = false,
        bool fallbackSelectedForExplicitRiskException = false,
        bool externalCryptoApprovedForProduction = false) => new(
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
        FallbackSelectedForExplicitRiskException: fallbackSelectedForExplicitRiskException,
        ExternalCryptoApprovedForProduction: externalCryptoApprovedForProduction,
        OfficialSupportEvidence: "Managed fallback; not a platform-native .NET provider.");
}

public sealed record MLKemProviderAuditGates(
    bool Fips203CodeMapReviewed,
    bool PositiveVectorsPassed,
    bool NegativeVectorsPassed,
    bool SideChannelReviewPassed,
    bool ReleaseDeviceBenchmarksRecorded,
    bool ExternalCryptoApprovedForProduction)
{
    public bool MaintainerRiskAcceptedNotCryptoApproved { get; init; }

    public static MLKemProviderAuditGates Open { get; } = new(
        Fips203CodeMapReviewed: false,
        PositiveVectorsPassed: false,
        NegativeVectorsPassed: false,
        SideChannelReviewPassed: false,
        ReleaseDeviceBenchmarksRecorded: false,
        ExternalCryptoApprovedForProduction: false);

    public static MLKemProviderAuditGates ClosedForFallbackProduction { get; } = new(
        Fips203CodeMapReviewed: true,
        PositiveVectorsPassed: true,
        NegativeVectorsPassed: true,
        SideChannelReviewPassed: true,
        ReleaseDeviceBenchmarksRecorded: true,
        ExternalCryptoApprovedForProduction: true);

    public static MLKemProviderAuditGates RiskAcceptedForEmsiDmProductionFallback { get; } =
        Open with
        {
            PositiveVectorsPassed = true,
            NegativeVectorsPassed = true,
            ReleaseDeviceBenchmarksRecorded = true,
            MaintainerRiskAcceptedNotCryptoApproved = true,
        };

    public bool AuditAcceptedForFallbackProduction =>
        Fips203CodeMapReviewed &&
        PositiveVectorsPassed &&
        NegativeVectorsPassed &&
        SideChannelReviewPassed &&
        ReleaseDeviceBenchmarksRecorded &&
        ExternalCryptoApprovedForProduction;

    public bool FallbackProductionReady =>
        AuditAcceptedForFallbackProduction;

    public bool FallbackSelectableForExplicitRiskException =>
        MaintainerRiskAcceptedNotCryptoApproved &&
        PositiveVectorsPassed &&
        NegativeVectorsPassed &&
        ReleaseDeviceBenchmarksRecorded &&
        !ExternalCryptoApprovedForProduction;
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
    bool AllowsExplicitRiskExceptionFallbackInProduction,
    MLKemProviderAuditGates AuditGates)
{
    public enum ProviderEnvironment
    {
        Production,
        NonProduction,
    }

    public static MLKemProviderPolicy Production(
        bool allowsFallbackInProduction = false,
        bool allowsExplicitRiskExceptionFallbackInProduction = false,
        MLKemProviderAuditGates? auditGates = null) =>
        new(
            Environment: ProviderEnvironment.Production,
            AllowsFallbackInProduction: allowsFallbackInProduction,
            AllowsExplicitRiskExceptionFallbackInProduction: allowsExplicitRiskExceptionFallbackInProduction,
            AuditGates: auditGates ?? MLKemProviderAuditGates.Open);

    public static MLKemProviderPolicy NonProduction() =>
        new(
            Environment: ProviderEnvironment.NonProduction,
            AllowsFallbackInProduction: false,
            AllowsExplicitRiskExceptionFallbackInProduction: false,
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

        if (policy.Environment == ProviderEnvironment.NonProduction)
        {
            return MLKemProviderSelection.Selected(MLKemProviderMetadata.ManagedCSharpMLKem768());
        }

        if (!policy.AllowsFallbackInProduction &&
            !policy.AllowsExplicitRiskExceptionFallbackInProduction)
        {
            return MLKemProviderSelection.FailClosed(MLKemProviderFailureReason.FallbackDisallowedInProduction);
        }

        if (policy.AllowsFallbackInProduction && policy.AuditGates.FallbackProductionReady)
        {
            return MLKemProviderSelection.Selected(
                MLKemProviderMetadata.ManagedCSharpMLKem768(
                    fallbackAllowedInProduction: true,
                    externalCryptoApprovedForProduction: true));
        }

        if (policy.AllowsExplicitRiskExceptionFallbackInProduction &&
            policy.AuditGates.FallbackSelectableForExplicitRiskException)
        {
            return MLKemProviderSelection.Selected(
                MLKemProviderMetadata.ManagedCSharpMLKem768(
                    fallbackSelectedForExplicitRiskException: true,
                    externalCryptoApprovedForProduction: false));
        }

        return MLKemProviderSelection.FailClosed(MLKemProviderFailureReason.FallbackAuditIncomplete);
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
