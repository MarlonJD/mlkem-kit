import CryptoKit
import Foundation
import MLKEMNativeSwift

private enum TimingSanityError: Error {
    case invalidJSON
}

private let warmupCount = 20
private let sampleCount = 200

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

private func observe(_ sharedSecret: SymmetricKey, into accumulator: inout Int) {
    sharedSecret.withUnsafeBytes { bytes in
        accumulator ^= Int(bytes[0])
    }
}

private func runTimingSanity() throws -> String {
    let privateKey = try MLKEMNative768.PrivateKey.generate()
    let ciphertexts = try (0..<sampleCount).map { _ in
        try privateKey.publicKey.encapsulate().ciphertext
    }
    let tamperedCiphertexts = ciphertexts.map { ciphertext -> Data in
        var tampered = ciphertext
        tampered[tampered.startIndex] ^= 0x01
        return tampered
    }

    var accumulator = 0
    var validIndex = 0
    let validMs = try measure {
        let sharedSecret = try privateKey.decapsulate(ciphertexts[validIndex])
        validIndex = (validIndex + 1) % ciphertexts.count
        observe(sharedSecret, into: &accumulator)
    }

    var tamperedIndex = 0
    let tamperedMs = try measure {
        let sharedSecret = try privateKey.decapsulate(tamperedCiphertexts[tamperedIndex])
        tamperedIndex = (tamperedIndex + 1) % tamperedCiphertexts.count
        observe(sharedSecret, into: &accumulator)
    }

    if accumulator == Int.min {
        throw TimingSanityError.invalidJSON
    }

    let validP50 = percentile50(validMs)
    let tamperedP50 = percentile50(tamperedMs)
    let absoluteDelta = abs(validP50 - tamperedP50)
    let ratio = validP50 == 0 ? 0 : tamperedP50 / validP50
    let environment = ProcessInfo.processInfo.environment
    let result: [String: Any] = [
        "schemaVersion": 1,
        "status": "complete",
        "measuredAt": ISO8601DateFormatter().string(from: Date()),
        "platform": "macOS",
        "device": environment["MLKEM_TIMING_DEVICE"] ?? "local macOS host",
        "os": environment["MLKEM_TIMING_OS"] ?? ProcessInfo.processInfo.operatingSystemVersionString,
        "sourceRevision": environment["MLKEM_TIMING_SOURCE_REVISION"] ?? "package-local dirty worktree",
        "configuration": "release",
        "sampleCount": sampleCount,
        "validDecapsulationP50Ms": validP50,
        "tamperedDecapsulationP50Ms": tamperedP50,
        "absoluteDeltaP50Ms": absoluteDelta,
        "ratioP50": ratio,
        "notes": "Valid ciphertext and single-byte-tampered ciphertext decapsulation p50 timing sanity on local macOS Release build.",
        "claimLimits": "Timing sanity evidence only; not formal constant-time proof."
    ]

    let data = try JSONSerialization.data(withJSONObject: result, options: [.prettyPrinted, .sortedKeys])
    guard let json = String(data: data, encoding: .utf8) else {
        throw TimingSanityError.invalidJSON
    }
    return json
}

print("MLKEM_TIMING_SANITY_JSON_BEGIN")
print(try runTimingSanity())
print("MLKEM_TIMING_SANITY_JSON_END")
