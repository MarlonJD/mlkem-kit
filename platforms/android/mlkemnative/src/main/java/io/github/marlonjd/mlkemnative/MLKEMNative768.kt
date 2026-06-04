package io.github.marlonjd.mlkemnative

import java.security.GeneralSecurityException
import java.security.ProviderException
import java.security.SecureRandom

sealed class MLKEMException(
    message: String,
    cause: Throwable? = null,
) : GeneralSecurityException(message, cause) {
    class InvalidPublicKey(message: String = "Invalid ML-KEM-768 public key") :
        MLKEMException(message)

    class InvalidPrivateKeyRepresentation(
        message: String = "Invalid ML-KEM-768 private key representation",
    ) : MLKEMException(message)

    class InvalidCiphertext(message: String = "Invalid ML-KEM-768 ciphertext") :
        MLKEMException(message)

    class InvalidIncrementalHeader(
        message: String = "Invalid ML-KEM-768 incremental header",
    ) : MLKEMException(message)

    class InvalidEncapsulationKeyVector(
        message: String = "Invalid ML-KEM-768 encapsulation key vector",
    ) : MLKEMException(message)

    class InvalidIncrementalEncapsulationSecret(
        message: String = "Invalid ML-KEM-768 incremental encapsulation secret",
    ) : MLKEMException(message)

    class RandomGenerationFailed(cause: Throwable) :
        MLKEMException("Secure random generation failed", cause)

    class OperationFailed(message: String = "ML-KEM-768 operation failed") :
        MLKEMException(message)
}

object MLKEMNative768 {
    const val PUBLIC_KEY_BYTES = 1184
    const val CIPHERTEXT_BYTES = 1088
    const val SHARED_SECRET_BYTES = 32
    const val SECRET_KEY_BYTES = 2400
    const val KEYPAIR_SEED_BYTES = 64
    const val ENCAPSULATION_SEED_BYTES = 32
    const val INCREMENTAL_HEADER_BYTES = 64
    const val ENCAPSULATION_KEY_VECTOR_BYTES = 1152
    const val CIPHERTEXT_PART1_BYTES = 960
    const val CIPHERTEXT_PART2_BYTES = 128
    const val INCREMENTAL_ENCAPSULATION_SECRET_BYTES = 64

    const val publicKeyBytes = PUBLIC_KEY_BYTES
    const val ciphertextBytes = CIPHERTEXT_BYTES
    const val sharedSecretBytes = SHARED_SECRET_BYTES
    const val incrementalHeaderBytes = INCREMENTAL_HEADER_BYTES
    const val encapsulationKeyVectorBytes = ENCAPSULATION_KEY_VECTOR_BYTES
    const val ciphertextPart1Bytes = CIPHERTEXT_PART1_BYTES
    const val ciphertextPart2Bytes = CIPHERTEXT_PART2_BYTES
    const val incrementalEncapsulationSecretBytes = INCREMENTAL_ENCAPSULATION_SECRET_BYTES

    private const val MAGIC = "KMLK1"
    private const val EK_SEED_OFFSET = ENCAPSULATION_KEY_VECTOR_BYTES
    private const val HEADER_HASH_OFFSET = ENCAPSULATION_SEED_BYTES
    private val magicBytes = MAGIC.encodeToByteArray()
    private val secureRandom = SecureRandom()

    const val PRIVATE_KEY_REPRESENTATION_BYTES =
        5 + KEYPAIR_SEED_BYTES + PUBLIC_KEY_BYTES

    class PrivateKey private constructor(
        private val secretKey: ByteArray,
        private val representationBytes: ByteArray,
        val publicKey: PublicKey,
    ) {
        /**
         * Exportable private-key representation: KMLK1 || seed64 || publicKey1184.
         * The seed portion can recreate the private key. Treat returned arrays as secret
         * material; do not log them; store them only in caller-approved protected storage;
         * clear caller-owned mutable copies when no longer needed.
         */
        val representation: ByteArray
            get() = representationBytes.copyOf()

        fun decapsulate(ciphertext: ByteArray): ByteArray {
            if (ciphertext.size != CIPHERTEXT_BYTES) {
                throw MLKEMException.InvalidCiphertext()
            }

            return PureKotlinMLKEM768.decapsulate(ciphertext.copyOf(), secretKey)
        }

        fun decapsulateParts(
            ciphertextPart1: ByteArray,
            ciphertextPart2: ByteArray,
        ): ByteArray = MLKEMNative768.decapsulateParts(this, ciphertextPart1, ciphertextPart2)

        companion object {
            fun generate(): PrivateKey {
                val seed = randomBytes(KEYPAIR_SEED_BYTES)
                try {
                    return fromSeed(seed)
                } finally {
                    seed.fill(0)
                }
            }

            /**
             * Exportable private-key representation: KMLK1 || seed64 || publicKey1184.
             * The seed portion can recreate the private key. Treat returned arrays as secret
             * material; do not log them; store them only in caller-approved protected storage;
             * clear caller-owned mutable copies when no longer needed.
             */
            fun fromRepresentation(representation: ByteArray): PrivateKey {
                if (representation.size != PRIVATE_KEY_REPRESENTATION_BYTES) {
                    throw MLKEMException.InvalidPrivateKeyRepresentation()
                }

                if (!representation.startsWithMagic()) {
                    throw MLKEMException.InvalidPrivateKeyRepresentation()
                }

                val seedStart = magicBytes.size
                val publicKeyStart = seedStart + KEYPAIR_SEED_BYTES
                val seed = representation.copyOfRange(seedStart, publicKeyStart)
                val expectedPublicKey = representation.copyOfRange(
                    publicKeyStart,
                    PRIVATE_KEY_REPRESENTATION_BYTES,
                )
                try {
                    val generated = deriveKeypair(seed)

                    if (!generated.publicKey.contentEquals(expectedPublicKey)) {
                        throw MLKEMException.InvalidPrivateKeyRepresentation()
                    }

                    return buildPrivateKey(seed, generated.publicKey, generated.secretKey)
                } finally {
                    seed.fill(0)
                }
            }

            internal fun fromSeedForTesting(seed: ByteArray): PrivateKey {
                if (seed.size != KEYPAIR_SEED_BYTES) {
                    throw MLKEMException.InvalidPrivateKeyRepresentation()
                }
                return fromSeed(seed.copyOf())
            }

            private fun fromSeed(seed: ByteArray): PrivateKey {
                val generated = deriveKeypair(seed)
                return buildPrivateKey(seed, generated.publicKey, generated.secretKey)
            }

            private fun buildPrivateKey(
                seed: ByteArray,
                publicKey: ByteArray,
                secretKey: ByteArray,
            ): PrivateKey {
                if (!PureKotlinMLKEM768.checkSecretKey(secretKey)) {
                    throw MLKEMException.OperationFailed("ML-KEM-768 secret key validation failed")
                }

                val representation = ByteArray(PRIVATE_KEY_REPRESENTATION_BYTES)
                magicBytes.copyInto(representation, 0)
                seed.copyInto(representation, magicBytes.size)
                publicKey.copyInto(representation, magicBytes.size + KEYPAIR_SEED_BYTES)

                return PrivateKey(
                    secretKey = secretKey.copyOf(),
                    representationBytes = representation,
                    publicKey = PublicKey(publicKey),
                )
            }
        }
    }

    class PublicKey(rawRepresentation: ByteArray) {
        private val rawRepresentationBytes: ByteArray = rawRepresentation.copyOf()

        val rawRepresentation: ByteArray
            get() = rawRepresentationBytes.copyOf()

        init {
            if (rawRepresentationBytes.size != PUBLIC_KEY_BYTES ||
                !PureKotlinMLKEM768.checkPublicKey(rawRepresentationBytes)
            ) {
                throw MLKEMException.InvalidPublicKey()
            }
        }

        fun encapsulate(): Encapsulation {
            val coins = randomBytes(ENCAPSULATION_SEED_BYTES)
            try {
                return encapsulateDerand(coins)
            } finally {
                coins.fill(0)
            }
        }

        internal fun encapsulateDerand(coins: ByteArray): Encapsulation {
            if (coins.size != ENCAPSULATION_SEED_BYTES) {
                throw MLKEMException.OperationFailed("Invalid ML-KEM-768 encapsulation seed")
            }

            val localCoins = coins.copyOf()
            try {
                val output = PureKotlinMLKEM768.encapsulateDerand(rawRepresentationBytes, localCoins)
                return Encapsulation(output.ciphertext, output.sharedSecret)
            } finally {
                localCoins.fill(0)
            }
        }
    }

    data class Encapsulation internal constructor(
        private val ciphertextBytes: ByteArray,
        private val sharedSecretBytes: ByteArray,
    ) {
        val ciphertext: ByteArray
            get() = ciphertextBytes.copyOf()

        val sharedSecret: ByteArray
            get() = sharedSecretBytes.copyOf()

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Encapsulation) return false
            return ciphertextBytes.contentEquals(other.ciphertextBytes) &&
                sharedSecretBytes.contentEquals(other.sharedSecretBytes)
        }

        override fun hashCode(): Int {
            var result = ciphertextBytes.contentHashCode()
            result = 31 * result + sharedSecretBytes.contentHashCode()
            return result
        }
    }

    class IncrementalPublicKey internal constructor(
        private val headerBytes: ByteArray,
        private val encapsulationKeyVectorBytes: ByteArray,
    ) {
        val header: ByteArray
            get() = headerBytes.copyOf()

        val encapsulationKeyVector: ByteArray
            get() = encapsulationKeyVectorBytes.copyOf()

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is IncrementalPublicKey) return false
            return headerBytes.contentEquals(other.headerBytes) &&
                encapsulationKeyVectorBytes.contentEquals(other.encapsulationKeyVectorBytes)
        }

        override fun hashCode(): Int {
            var result = headerBytes.contentHashCode()
            result = 31 * result + encapsulationKeyVectorBytes.contentHashCode()
            return result
        }
    }

    class IncrementalEncapsulationPart1 internal constructor(
        private val encapsulationSecretBytes: ByteArray,
        private val ciphertextPart1Bytes: ByteArray,
        private val sharedSecretBytes: ByteArray,
    ) {
        val encapsulationSecret: ByteArray
            get() = encapsulationSecretBytes.copyOf()

        val encapsSecret: ByteArray
            get() = encapsulationSecret

        val ciphertextPart1: ByteArray
            get() = ciphertextPart1Bytes.copyOf()

        val sharedSecret: ByteArray
            get() = sharedSecretBytes.copyOf()

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is IncrementalEncapsulationPart1) return false
            return encapsulationSecretBytes.contentEquals(other.encapsulationSecretBytes) &&
                ciphertextPart1Bytes.contentEquals(other.ciphertextPart1Bytes) &&
                sharedSecretBytes.contentEquals(other.sharedSecretBytes)
        }

        override fun hashCode(): Int {
            var result = encapsulationSecretBytes.contentHashCode()
            result = 31 * result + ciphertextPart1Bytes.contentHashCode()
            result = 31 * result + sharedSecretBytes.contentHashCode()
            return result
        }
    }

    fun publicKeyToIncremental(publicKey: PublicKey): IncrementalPublicKey =
        publicKeyToIncremental(publicKey.rawRepresentation)

    fun publicKeyToIncremental(publicKey: ByteArray): IncrementalPublicKey {
        val rawPublicKey = PublicKey(publicKey).rawRepresentation
        val header = ByteArray(INCREMENTAL_HEADER_BYTES)
        rawPublicKey.copyInto(
            destination = header,
            destinationOffset = 0,
            startIndex = EK_SEED_OFFSET,
            endIndex = PUBLIC_KEY_BYTES,
        )
        sha3256(rawPublicKey).copyInto(header, HEADER_HASH_OFFSET)

        return IncrementalPublicKey(
            headerBytes = header,
            encapsulationKeyVectorBytes = rawPublicKey.copyOfRange(0, EK_SEED_OFFSET),
        )
    }

    fun publicKeyFromIncremental(
        header: ByteArray,
        encapsulationKeyVector: ByteArray,
    ): ByteArray {
        if (header.size != INCREMENTAL_HEADER_BYTES) {
            throw MLKEMException.InvalidIncrementalHeader()
        }
        if (encapsulationKeyVector.size != ENCAPSULATION_KEY_VECTOR_BYTES) {
            throw MLKEMException.InvalidEncapsulationKeyVector()
        }

        val publicKey = ByteArray(PUBLIC_KEY_BYTES)
        encapsulationKeyVector.copyInto(publicKey)
        header.copyInto(
            destination = publicKey,
            destinationOffset = EK_SEED_OFFSET,
            startIndex = 0,
            endIndex = ENCAPSULATION_SEED_BYTES,
        )

        val expectedHash = sha3256(publicKey)
        val headerHash = header.copyOfRange(HEADER_HASH_OFFSET, INCREMENTAL_HEADER_BYTES)
        if (!expectedHash.contentEquals(headerHash)) {
            throw MLKEMException.InvalidIncrementalHeader(
                "Invalid ML-KEM-768 incremental header hash",
            )
        }

        PublicKey(publicKey)
        return publicKey
    }

    fun encapsulatePart1(header: ByteArray): IncrementalEncapsulationPart1 {
        if (header.size != INCREMENTAL_HEADER_BYTES) {
            throw MLKEMException.InvalidIncrementalHeader()
        }

        val coins = randomBytes(ENCAPSULATION_SEED_BYTES)
        try {
            return encapsulatePart1Derand(header, coins)
        } finally {
            coins.fill(0)
        }
    }

    @JvmSynthetic
    internal fun encapsulatePart1DerandForTesting(
        header: ByteArray,
        randomness: ByteArray,
    ): IncrementalEncapsulationPart1 {
        if (header.size != INCREMENTAL_HEADER_BYTES) {
            throw MLKEMException.InvalidIncrementalHeader()
        }
        if (randomness.size != ENCAPSULATION_SEED_BYTES) {
            throw MLKEMException.OperationFailed("Invalid ML-KEM-768 encapsulation randomness")
        }

        return encapsulatePart1Derand(header, randomness)
    }

    private fun encapsulatePart1Derand(
        header: ByteArray,
        coins: ByteArray,
    ): IncrementalEncapsulationPart1 {
        val localCoins = coins.copyOf()
        try {
            val output = PureKotlinMLKEM768.encapsulatePart1Derand(header.copyOf(), localCoins)
            return IncrementalEncapsulationPart1(
                encapsulationSecretBytes = output.encapsulationSecret,
                ciphertextPart1Bytes = output.ciphertextPart1,
                sharedSecretBytes = output.sharedSecret,
            )
        } finally {
            localCoins.fill(0)
        }
    }

    fun encapsulatePart2(
        encapsSecret: ByteArray,
        header: ByteArray,
        encapsulationKeyVector: ByteArray,
    ): ByteArray {
        if (encapsSecret.size != INCREMENTAL_ENCAPSULATION_SECRET_BYTES) {
            throw MLKEMException.InvalidIncrementalEncapsulationSecret()
        }

        val publicKey = publicKeyFromIncremental(header, encapsulationKeyVector)
        return PureKotlinMLKEM768.encapsulatePart2(encapsSecret.copyOf(), publicKey)
    }

    fun decapsulateParts(
        privateKey: PrivateKey,
        ciphertextPart1: ByteArray,
        ciphertextPart2: ByteArray,
    ): ByteArray {
        if (ciphertextPart1.size != CIPHERTEXT_PART1_BYTES) {
            throw MLKEMException.InvalidCiphertext("Invalid ML-KEM-768 ciphertext part1")
        }
        if (ciphertextPart2.size != CIPHERTEXT_PART2_BYTES) {
            throw MLKEMException.InvalidCiphertext("Invalid ML-KEM-768 ciphertext part2")
        }

        val ciphertext = ByteArray(CIPHERTEXT_BYTES)
        ciphertextPart1.copyInto(ciphertext)
        ciphertextPart2.copyInto(ciphertext, CIPHERTEXT_PART1_BYTES)
        return privateKey.decapsulate(ciphertext)
    }

    internal fun keypairDerandForTesting(seed: ByteArray): Pair<ByteArray, ByteArray> =
        deriveKeypair(seed.copyOf()).let { it.publicKey to it.secretKey }

    internal fun encapsulateDerandForTesting(
        publicKey: ByteArray,
        coins: ByteArray,
    ): Encapsulation = PublicKey(publicKey).encapsulateDerand(coins)

    private fun deriveKeypair(seed: ByteArray): NativeKeypair {
        if (seed.size != KEYPAIR_SEED_BYTES) {
            throw MLKEMException.OperationFailed("Invalid ML-KEM-768 keypair seed")
        }

        val output = PureKotlinMLKEM768.keypairDerand(seed)
        return NativeKeypair(output.publicKey, output.secretKey)
    }

    private fun randomBytes(size: Int): ByteArray {
        val output = ByteArray(size)
        try {
            secureRandom.nextBytes(output)
        } catch (exception: ProviderException) {
            throw MLKEMException.RandomGenerationFailed(exception)
        } catch (exception: RuntimeException) {
            throw MLKEMException.RandomGenerationFailed(exception)
        }
        return output
    }

    private fun ByteArray.startsWithMagic(): Boolean {
        if (size < magicBytes.size) return false
        for (index in magicBytes.indices) {
            if (this[index] != magicBytes[index]) return false
        }
        return true
    }

    private fun sha3256(input: ByteArray): ByteArray =
        PureKotlinMLKEM768.sha3256(input)

    private data class NativeKeypair(
        val publicKey: ByteArray,
        val secretKey: ByteArray,
    )

}
