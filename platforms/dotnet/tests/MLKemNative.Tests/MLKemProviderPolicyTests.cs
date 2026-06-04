using Xunit;

namespace MLKemNative.Tests;

public sealed class MLKemProviderPolicyTests
{
    [Fact]
    public void DotNetProviderIsSelectedOnlyWhenBuiltInMlKemIsSupported()
    {
        var runtime = new MLKemDotNetRuntimeCapabilities(
            BuiltInMLKemSupported: true,
            BuiltInProviderSupportsKeyGeneration: true,
            BuiltInProviderSupportsEncapsulation: true,
            BuiltInProviderSupportsDecapsulation: true,
            ManagedFallbackAvailable: true,
            RuntimeDescription: ".NET 10 on supported Windows build");

        MLKemProviderSelection selection = MLKemProviderPolicy.SelectDotNetProvider(
            runtime,
            MLKemProviderPolicy.Production());

        Assert.Equal("dotnet-system-security-cryptography-mlkem768", selection.Provider?.ProviderId);
        Assert.True(selection.Provider!.IsPlatformNative);
        Assert.False(selection.Provider.UsesPInvoke);
        Assert.False(selection.Provider.UsesCOrFfi);
    }

    [Fact]
    public void BuiltInProviderMustExposeEveryKemOperation()
    {
        var runtime = new MLKemDotNetRuntimeCapabilities(
            BuiltInMLKemSupported: true,
            BuiltInProviderSupportsKeyGeneration: true,
            BuiltInProviderSupportsEncapsulation: true,
            BuiltInProviderSupportsDecapsulation: false,
            ManagedFallbackAvailable: true,
            RuntimeDescription: ".NET 10 preview without full KEM operations");

        MLKemProviderSelection selection = MLKemProviderPolicy.SelectDotNetProvider(
            runtime,
            MLKemProviderPolicy.Production());

        Assert.Null(selection.Provider);
        Assert.Equal(MLKemProviderFailureReason.BuiltInProviderIncomplete, selection.FailureReason);
    }

    [Fact]
    public void ProductionFallbackFailsClosedWhenAuditGatesAreIncomplete()
    {
        var runtime = new MLKemDotNetRuntimeCapabilities(
            BuiltInMLKemSupported: false,
            BuiltInProviderSupportsKeyGeneration: false,
            BuiltInProviderSupportsEncapsulation: false,
            BuiltInProviderSupportsDecapsulation: false,
            ManagedFallbackAvailable: true,
            RuntimeDescription: ".NET runtime without built-in ML-KEM");

        MLKemProviderSelection selection = MLKemProviderPolicy.SelectDotNetProvider(
            runtime,
            MLKemProviderPolicy.Production(allowsFallbackInProduction: true));

        Assert.Null(selection.Provider);
        Assert.Equal(MLKemProviderFailureReason.FallbackAuditIncomplete, selection.FailureReason);
    }

    [Fact]
    public void AuditedManagedFallbackRequiresExplicitPolicyAllowanceInProduction()
    {
        var runtime = new MLKemDotNetRuntimeCapabilities(
            BuiltInMLKemSupported: false,
            BuiltInProviderSupportsKeyGeneration: false,
            BuiltInProviderSupportsEncapsulation: false,
            BuiltInProviderSupportsDecapsulation: false,
            ManagedFallbackAvailable: true,
            RuntimeDescription: ".NET runtime without built-in ML-KEM");

        MLKemProviderSelection selection = MLKemProviderPolicy.SelectDotNetProvider(
            runtime,
            MLKemProviderPolicy.Production(
                auditGates: MLKemProviderAuditGates.ClosedForFallbackProduction));

        Assert.Null(selection.Provider);
        Assert.Equal(MLKemProviderFailureReason.FallbackDisallowedInProduction, selection.FailureReason);
    }

    [Fact]
    public void ProductionFallbackFailsClosedWhenSingleAuditGateIsOpen()
    {
        var runtime = new MLKemDotNetRuntimeCapabilities(
            BuiltInMLKemSupported: false,
            BuiltInProviderSupportsKeyGeneration: false,
            BuiltInProviderSupportsEncapsulation: false,
            BuiltInProviderSupportsDecapsulation: false,
            ManagedFallbackAvailable: true,
            RuntimeDescription: ".NET runtime without built-in ML-KEM");
        var gates = new MLKemProviderAuditGates(
            Fips203CodeMapReviewed: true,
            PositiveVectorsPassed: true,
            NegativeVectorsPassed: true,
            SideChannelReviewPassed: true,
            ReleaseDeviceBenchmarksRecorded: false,
            ExternalCryptoReviewAccepted: true);

        MLKemProviderSelection selection = MLKemProviderPolicy.SelectDotNetProvider(
            runtime,
            MLKemProviderPolicy.Production(
                allowsFallbackInProduction: true,
                auditGates: gates));

        Assert.Null(selection.Provider);
        Assert.Equal(MLKemProviderFailureReason.FallbackAuditIncomplete, selection.FailureReason);
    }

    [Fact]
    public void ProductionFallbackRequiresBothPolicyAllowanceAndClosedAuditGates()
    {
        var runtime = new MLKemDotNetRuntimeCapabilities(
            BuiltInMLKemSupported: false,
            BuiltInProviderSupportsKeyGeneration: false,
            BuiltInProviderSupportsEncapsulation: false,
            BuiltInProviderSupportsDecapsulation: false,
            ManagedFallbackAvailable: true,
            RuntimeDescription: ".NET runtime without built-in ML-KEM");
        (MLKemProviderPolicy Policy, MLKemProviderFailureReason ExpectedFailure)[] cases =
        {
            (
                MLKemProviderPolicy.Production(),
                MLKemProviderFailureReason.FallbackDisallowedInProduction),
            (
                MLKemProviderPolicy.Production(allowsFallbackInProduction: true),
                MLKemProviderFailureReason.FallbackAuditIncomplete),
            (
                MLKemProviderPolicy.Production(auditGates: MLKemProviderAuditGates.ClosedForFallbackProduction),
                MLKemProviderFailureReason.FallbackDisallowedInProduction),
        };

        foreach ((MLKemProviderPolicy policy, MLKemProviderFailureReason expectedFailure) in cases)
        {
            MLKemProviderSelection selection = MLKemProviderPolicy.SelectDotNetProvider(runtime, policy);

            Assert.Null(selection.Provider);
            Assert.Equal(expectedFailure, selection.FailureReason);
        }
    }

    [Fact]
    public void AuditedManagedFallbackRequiresPolicyAllowanceInProduction()
    {
        var runtime = new MLKemDotNetRuntimeCapabilities(
            BuiltInMLKemSupported: false,
            BuiltInProviderSupportsKeyGeneration: false,
            BuiltInProviderSupportsEncapsulation: false,
            BuiltInProviderSupportsDecapsulation: false,
            ManagedFallbackAvailable: true,
            RuntimeDescription: ".NET runtime without built-in ML-KEM");

        MLKemProviderSelection selection = MLKemProviderPolicy.SelectDotNetProvider(
            runtime,
            MLKemProviderPolicy.Production(
                allowsFallbackInProduction: true,
                auditGates: MLKemProviderAuditGates.ClosedForFallbackProduction));

        Assert.Equal("csharp-managed-mlkem768", selection.Provider?.ProviderId);
        Assert.Equal("C#", selection.Provider?.ImplementationLanguage);
        Assert.True(selection.Provider!.FallbackAllowedInProduction);
    }

    [Fact]
    public void ManagedFallbackMetadataBlocksNativeDependencies()
    {
        MLKemProviderMetadata provider = MLKemProviderMetadata.ManagedCSharpMLKem768();

        Assert.False(provider.UsesPInvoke);
        Assert.False(provider.UsesCOrFfi);
        Assert.Null(provider.NativeLibraryDependency);
        Assert.False(provider.FallbackAllowedInProduction);
        Assert.Equal(MLKemPrivateKeyExportPolicy.ExportableSeedRepresentation, provider.PrivateKeyExportPolicy);
    }
}
