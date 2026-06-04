import CryptoKit
import Darwin
import Foundation
import MLKEMNativeSwift

private enum BenchmarkError: Error {
    case invalidJSON
}

private let warmupCount = 10
private let sampleCount = 200

private func allocatedBytes() -> UInt64 {
    guard let zone = malloc_default_zone() else {
        return 0
    }
    var statistics = malloc_statistics_t()
    malloc_zone_statistics(zone, &statistics)
    return UInt64(statistics.size_in_use)
}

private func measure(_ operation: () throws -> Void) rethrows -> [Double] {
    for _ in 0..<warmupCount {
        try operation()
    }

    var samples = [Double]()
    samples.reserveCapacity(sampleCount)
    for _ in 0..<sampleCount {
        let start = DispatchTime.now().uptimeNanoseconds
        try operation()
        let end = DispatchTime.now().uptimeNanoseconds
        samples.append(Double(end - start) / 1_000_000.0)
    }
    return samples
}

private func percentile50(_ values: [Double]) -> Double {
    let sorted = values.sorted()
    return sorted[sorted.count / 2]
}

private func runBenchmark() throws -> String {
    var peakAllocatedBytes = allocatedBytes()
    var accumulator = 0

    func observePeak() {
        peakAllocatedBytes = max(peakAllocatedBytes, allocatedBytes())
    }

    let keyGenerationMs = try measure {
        let privateKey = try MLKEMNative768.PrivateKey.generate()
        accumulator ^= Int(privateKey.publicKey.rawRepresentation[0])
        observePeak()
    }

    let encapsulationKey = try MLKEMNative768.PrivateKey.generate()
    let publicKey = encapsulationKey.publicKey
    let encapsulationMs = try measure {
        let encapsulated = try publicKey.encapsulate()
        accumulator ^= Int(encapsulated.ciphertext[0])
        observePeak()
    }

    let decapsulationKey = try MLKEMNative768.PrivateKey.generate()
    let ciphertexts = try (0..<sampleCount).map { _ in
        try decapsulationKey.publicKey.encapsulate().ciphertext
    }
    var decapsulationIndex = 0
    let decapsulationMs = try measure {
        let sharedSecret = try decapsulationKey.decapsulate(ciphertexts[decapsulationIndex])
        decapsulationIndex = (decapsulationIndex + 1) % ciphertexts.count
        sharedSecret.withUnsafeBytes { bytes in
            accumulator ^= Int(bytes[0])
        }
        observePeak()
    }

    observePeak()
    if accumulator == Int.min {
        fputs("unreachable accumulator value\n", stderr)
    }

    let environment = ProcessInfo.processInfo.environment
    let result: [String: Any] = [
        "schemaVersion": 1,
        "status": "partial",
        "results": [
            [
                "platform": "macOS",
                "device": environment["MLKEM_BENCHMARK_DEVICE"] ?? "Apple Silicon Mac",
                "osOrRuntime": environment["MLKEM_BENCHMARK_OS"] ?? ProcessInfo.processInfo.operatingSystemVersionString,
                "buildConfiguration": "release",
                "providerId": "swift-pure-mlkem768",
                "keyGenerationP50Ms": percentile50(keyGenerationMs),
                "encapsulationP50Ms": percentile50(encapsulationMs),
                "decapsulationP50Ms": percentile50(decapsulationMs),
                "peakAllocationBytes": Int(peakAllocatedBytes),
                "sampleCount": sampleCount,
                "measuredAt": ISO8601DateFormatter().string(from: Date())
            ]
        ]
    ]

    let data = try JSONSerialization.data(withJSONObject: result, options: [.prettyPrinted, .sortedKeys])
    guard let json = String(data: data, encoding: .utf8) else {
        throw BenchmarkError.invalidJSON
    }
    return json
}

print(try runBenchmark())
