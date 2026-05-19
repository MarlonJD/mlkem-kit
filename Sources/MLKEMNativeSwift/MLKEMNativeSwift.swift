import CryptoKit
import Foundation
import Security

/// Errors thrown by the MLKEMNativeSwift wrapper.
public enum MLKEMError: Error, Equatable {
    case invalidPublicKey
    case invalidPrivateKeyRepresentation
    case invalidCiphertext
    case randomGenerationFailed
    case operationFailed
}

/// ML-KEM-768 operations and byte-size constants.
public enum MLKEMNative768 {
    /// Raw ML-KEM-768 public key length, in bytes.
    public static let publicKeyBytes = PureSwiftMLKEM768.publicKeyBytes
    /// Raw ML-KEM-768 ciphertext length, in bytes.
    public static let ciphertextBytes = PureSwiftMLKEM768.ciphertextBytes
    /// ML-KEM shared secret length, in bytes.
    public static let sharedSecretBytes = PureSwiftMLKEM768.sharedSecretBytes
    /// Regenerated in-memory secret key length, in bytes.
    public static let secretKeyBytes = PureSwiftMLKEM768.secretKeyBytes
    /// Deterministic key generation seed length, in bytes.
    public static let keypairSeedBytes = PureSwiftMLKEM768.keypairSeedBytes
    /// Deterministic encapsulation seed length, in bytes.
    public static let encapsulationSeedBytes = PureSwiftMLKEM768.encapsulationSeedBytes
    /// ML-KEM Braid header length: ek_seed || SHA3-256(public key).
    public static let incrementalHeaderBytes = PureSwiftMLKEM768.incrementalHeaderBytes
    /// Vector portion of an ML-KEM-768 public key, excluding the 32-byte seed.
    public static let encapsulationKeyVectorBytes = PureSwiftMLKEM768.encapsulationKeyVectorBytes
    /// First ciphertext component used by ML-KEM Braid.
    public static let ciphertextPart1Bytes = PureSwiftMLKEM768.ciphertextPart1Bytes
    /// Second ciphertext component used by ML-KEM Braid.
    public static let ciphertextPart2Bytes = PureSwiftMLKEM768.ciphertextPart2Bytes
    /// Opaque secret returned by Encaps1 and consumed by Encaps2.
    public static let incrementalEncapsulationSecretBytes = PureSwiftMLKEM768.incrementalEncapsulationSecretBytes

    /// Split public-key representation used by ML-KEM Braid.
    public struct IncrementalPublicKey: Sendable {
        public let header: Data
        public let encapsulationKeyVector: Data
        public let publicKey: PublicKey

        public init(header: Data, encapsulationKeyVector: Data) throws {
            guard header.count == incrementalHeaderBytes,
                  encapsulationKeyVector.count == encapsulationKeyVectorBytes else {
                throw MLKEMError.invalidPublicKey
            }

            self.header = header
            self.encapsulationKeyVector = encapsulationKeyVector
            self.publicKey = try PublicKey(
                rawRepresentation: PureSwiftMLKEM768.publicKeyFromIncremental(
                    header: header,
                    vector: encapsulationKeyVector
                )
            )
        }
    }

    /// Result of the first half of an incremental encapsulation.
    public struct IncrementalEncapsulation: Sendable {
        public let encapsulationSecret: Data
        public let ciphertextPart1: Data
        public let sharedSecret: SymmetricKey
    }

    /// An ML-KEM-768 private key.
    ///
    /// `representation` is a compact app-owned format:
    /// `KMLK1 || seed64 || publicKey1184`.
    public struct PrivateKey: Sendable {
        private static let magic = Data([0x4B, 0x4D, 0x4C, 0x4B, 0x31]) // KMLK1

        private let seed: Data
        private let secretKey: Data
        /// The public key corresponding to this private key.
        public let publicKey: PublicKey

        /// Generates a fresh ML-KEM-768 private key using `SecRandomCopyBytes`.
        public static func generate() throws -> PrivateKey {
            try PrivateKey(seed: randomBytes(count: keypairSeedBytes))
        }

        /// Loads a private key from `KMLK1 || seed64 || publicKey1184`.
        ///
        /// The in-memory ML-KEM secret key is regenerated from `seed64`, and the
        /// stored public key is verified against the regenerated public key.
        public init(representation: Data) throws {
            let expectedCount = Self.magic.count + keypairSeedBytes + publicKeyBytes
            guard representation.count == expectedCount,
                  representation.prefix(Self.magic.count) == Self.magic else {
                throw MLKEMError.invalidPrivateKeyRepresentation
            }

            let seedStart = Self.magic.count
            let seedEnd = seedStart + keypairSeedBytes
            let seed = Data(representation[seedStart..<seedEnd])
            let expectedPublicKey = Data(representation[seedEnd...])
            try self.init(seed: seed, expectedPublicKey: expectedPublicKey)
        }

        /// Loads a private key from a deterministic keygen seed and expected public key.
        ///
        /// This is useful for migrations from systems that separately expose the
        /// ML-KEM key generation seed and raw public key.
        public init(seedRepresentation: Data, publicKeyRepresentation: Data) throws {
            try self.init(seed: seedRepresentation, expectedPublicKey: publicKeyRepresentation)
        }

        var seedRepresentation: Data {
            seed
        }

        /// Compact private-key representation: `KMLK1 || seed64 || publicKey1184`.
        public var representation: Data {
            var data = Self.magic
            data.append(seed)
            data.append(publicKey.rawRepresentation)
            return data
        }

        init(seed: Data, expectedPublicKey: Data? = nil) throws {
            guard seed.count == keypairSeedBytes else {
                throw MLKEMError.invalidPrivateKeyRepresentation
            }

            let generated = try PureSwiftMLKEM768.keypairDerand(seed: seed)

            let publicKeyData = generated.publicKey
            if let expectedPublicKey, expectedPublicKey != publicKeyData {
                throw MLKEMError.invalidPrivateKeyRepresentation
            }

            self.seed = seed
            self.secretKey = generated.secretKey
            self.publicKey = try PublicKey(rawRepresentation: publicKeyData)
        }

        /// Decapsulates an ML-KEM-768 ciphertext and returns the shared secret.
        public func decapsulate(_ ciphertext: Data) throws -> SymmetricKey {
            guard ciphertext.count == ciphertextBytes else {
                throw MLKEMError.invalidCiphertext
            }

            return SymmetricKey(data: try PureSwiftMLKEM768.decapsulate(ciphertext: ciphertext, secretKey: secretKey))
        }

        /// Decapsulates split ML-KEM Braid ciphertext components.
        public func decapsulate(ciphertextPart1: Data, ciphertextPart2: Data) throws -> SymmetricKey {
            guard ciphertextPart1.count == ciphertextPart1Bytes,
                  ciphertextPart2.count == ciphertextPart2Bytes else {
                throw MLKEMError.invalidCiphertext
            }

            return SymmetricKey(data: try PureSwiftMLKEM768.decapsulateParts(
                ciphertextPart1: ciphertextPart1,
                ciphertextPart2: ciphertextPart2,
                secretKey: secretKey
            ))
        }
    }

    /// An ML-KEM-768 public key.
    public struct PublicKey: Sendable {
        /// Raw 1184-byte public-key representation.
        public let rawRepresentation: Data

        /// Loads and validates a raw ML-KEM-768 public key.
        public init(rawRepresentation: Data) throws {
            guard rawRepresentation.count == publicKeyBytes else {
                throw MLKEMError.invalidPublicKey
            }
            guard PureSwiftMLKEM768.checkPublicKey(rawRepresentation) else {
                throw MLKEMError.invalidPublicKey
            }
            self.rawRepresentation = rawRepresentation
        }

        /// Encapsulates to this public key and returns ciphertext plus shared secret.
        public func encapsulate() throws -> (ciphertext: Data, sharedSecret: SymmetricKey) {
            try encapsulate(seed: randomBytes(count: encapsulationSeedBytes))
        }

        func encapsulate(seed: Data) throws -> (ciphertext: Data, sharedSecret: SymmetricKey) {
            guard seed.count == encapsulationSeedBytes else {
                throw MLKEMError.operationFailed
            }

            let encapsulated = try PureSwiftMLKEM768.encapsulateDerand(publicKey: rawRepresentation, seed: seed)
            return (encapsulated.ciphertext, SymmetricKey(data: encapsulated.sharedSecret))
        }

        /// Returns the ML-KEM Braid split representation for this public key.
        public func incrementalRepresentation() throws -> IncrementalPublicKey {
            let split = try PureSwiftMLKEM768.publicKeyToIncremental(rawRepresentation)
            return try IncrementalPublicKey(header: split.header, encapsulationKeyVector: split.vector)
        }
    }

    /// Runs the first half of ML-KEM Braid encapsulation using fresh randomness.
    public static func encapsulatePart1(header: Data) throws -> IncrementalEncapsulation {
        try encapsulatePart1(header: header, seed: randomBytes(count: encapsulationSeedBytes))
    }

    static func encapsulatePart1(header: Data, seed: Data) throws -> IncrementalEncapsulation {
        guard header.count == incrementalHeaderBytes else {
            throw MLKEMError.invalidPublicKey
        }
        guard seed.count == encapsulationSeedBytes else {
            throw MLKEMError.operationFailed
        }

        let result = try PureSwiftMLKEM768.encapsulatePart1Derand(header: header, seed: seed)
        return IncrementalEncapsulation(
            encapsulationSecret: result.encapsulationSecret,
            ciphertextPart1: result.ciphertextPart1,
            sharedSecret: SymmetricKey(data: result.sharedSecret)
        )
    }

    /// Completes ML-KEM Braid encapsulation using the vector half of the public key.
    public static func encapsulatePart2(encapsulationSecret: Data,
                                        header: Data,
                                        encapsulationKeyVector: Data) throws -> Data {
        guard encapsulationSecret.count == incrementalEncapsulationSecretBytes else {
            throw MLKEMError.operationFailed
        }
        guard header.count == incrementalHeaderBytes,
              encapsulationKeyVector.count == encapsulationKeyVectorBytes else {
            throw MLKEMError.invalidPublicKey
        }

        return try PureSwiftMLKEM768.encapsulatePart2(
            encapsulationSecret: encapsulationSecret,
            header: header,
            vector: encapsulationKeyVector
        )
    }

    private static func randomBytes(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw MLKEMError.randomGenerationFailed
        }
        return Data(bytes)
    }
}
