using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using MLKemNative;

const int WarmupCount = 10;
const int SampleCount = 200;

long peakAllocationBytes = GC.GetTotalMemory(forceFullCollection: true);
int accumulator = 0;

void ObservePeak()
{
    peakAllocationBytes = Math.Max(peakAllocationBytes, GC.GetTotalMemory(forceFullCollection: false));
}

List<double> Measure(Action operation)
{
    for (int index = 0; index < WarmupCount; index += 1)
    {
        operation();
    }

    var samples = new List<double>(SampleCount);
    for (int index = 0; index < SampleCount; index += 1)
    {
        long start = Stopwatch.GetTimestamp();
        operation();
        long end = Stopwatch.GetTimestamp();
        samples.Add((end - start) * 1000.0 / Stopwatch.Frequency);
    }

    return samples;
}

double Percentile50(List<double> samples)
{
    samples.Sort();
    return samples[samples.Count / 2];
}

List<double> keyGenerationMs = Measure(() =>
{
    MLKemNative768.PrivateKey privateKey = MLKemNative768.PrivateKey.Generate();
    accumulator ^= privateKey.PublicKey.RawRepresentation[0];
    ObservePeak();
});

MLKemNative768.PrivateKey encapsulationKey = MLKemNative768.PrivateKey.Generate();
MLKemNative768.PublicKey publicKey = encapsulationKey.PublicKey;
List<double> encapsulationMs = Measure(() =>
{
    MLKemNative768.Encapsulation encapsulation = publicKey.Encapsulate();
    accumulator ^= encapsulation.Ciphertext[0];
    ObservePeak();
});

MLKemNative768.PrivateKey decapsulationKey = MLKemNative768.PrivateKey.Generate();
byte[][] ciphertexts = Enumerable.Range(0, SampleCount)
    .Select(_ => decapsulationKey.PublicKey.Encapsulate().Ciphertext)
    .ToArray();
int decapsulationIndex = 0;
List<double> decapsulationMs = Measure(() =>
{
    byte[] sharedSecret = decapsulationKey.Decapsulate(ciphertexts[decapsulationIndex]);
    decapsulationIndex = (decapsulationIndex + 1) % ciphertexts.Length;
    accumulator ^= sharedSecret[0];
    ObservePeak();
});

ObservePeak();
if (accumulator == int.MinValue)
{
    Console.Error.WriteLine("unreachable accumulator value");
}

string device = Environment.GetEnvironmentVariable("MLKEM_BENCHMARK_DEVICE")
    ?? (Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true"
        ? $"GitHub Actions {Environment.GetEnvironmentVariable("RUNNER_OS") ?? "Windows"} {Environment.GetEnvironmentVariable("RUNNER_ARCH") ?? RuntimeInformation.ProcessArchitecture.ToString()}"
        : $"{Environment.MachineName} {RuntimeInformation.ProcessArchitecture}");

string runtime = Environment.GetEnvironmentVariable("MLKEM_BENCHMARK_OS")
    ?? $"{RuntimeInformation.OSDescription}; {RuntimeInformation.FrameworkDescription}";

var payload = new
{
    schemaVersion = 1,
    status = "partial",
    results = new[]
    {
        new
        {
            platform = "dotnet",
            device,
            osOrRuntime = runtime,
            buildConfiguration = "release",
            providerId = "csharp-managed-mlkem768",
            keyGenerationP50Ms = Percentile50(keyGenerationMs),
            encapsulationP50Ms = Percentile50(encapsulationMs),
            decapsulationP50Ms = Percentile50(decapsulationMs),
            peakAllocationBytes,
            sampleCount = SampleCount,
            measuredAt = DateTimeOffset.UtcNow.ToString("O")
        }
    }
};

Console.WriteLine(JsonSerializer.Serialize(payload, new JsonSerializerOptions
{
    WriteIndented = true
}));
