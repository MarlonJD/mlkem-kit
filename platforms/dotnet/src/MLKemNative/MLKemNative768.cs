using System.Security.Cryptography;

namespace MLKemNative;

/// <summary>Base class for ML-KEM-768 API errors.</summary>
public abstract class MLKemException : CryptographicException
{
    private protected MLKemException(string message)
        : base(message)
    {
    }

    private protected MLKemException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public sealed class InvalidPublicKey : MLKemException
    {
        public InvalidPublicKey(string message = "Invalid ML-KEM-768 public key")
            : base(message)
        {
        }
    }

    public sealed class InvalidPrivateKeyRepresentation : MLKemException
    {
        public InvalidPrivateKeyRepresentation(string message = "Invalid ML-KEM-768 private key representation")
            : base(message)
        {
        }
    }

    public sealed class InvalidCiphertext : MLKemException
    {
        public InvalidCiphertext(string message = "Invalid ML-KEM-768 ciphertext")
            : base(message)
        {
        }
    }

    public sealed class InvalidIncrementalHeader : MLKemException
    {
        public InvalidIncrementalHeader(string message = "Invalid ML-KEM-768 incremental header")
            : base(message)
        {
        }
    }

    public sealed class InvalidEncapsulationKeyVector : MLKemException
    {
        public InvalidEncapsulationKeyVector(string message = "Invalid ML-KEM-768 encapsulation key vector")
            : base(message)
        {
        }
    }

    public sealed class InvalidIncrementalEncapsulationSecret : MLKemException
    {
        public InvalidIncrementalEncapsulationSecret(
            string message = "Invalid ML-KEM-768 incremental encapsulation secret")
            : base(message)
        {
        }
    }

    public sealed class RandomGenerationFailed : MLKemException
    {
        public RandomGenerationFailed(Exception cause)
            : base("Secure random generation failed", cause)
        {
        }
    }

    public sealed class OperationFailed : MLKemException
    {
        public OperationFailed(string message = "ML-KEM-768 operation failed")
            : base(message)
        {
        }
    }
}

/// <summary>Pure managed ML-KEM-768 operations and byte-size constants.</summary>
public static class MLKemNative768
{
    public const int PublicKeyBytes = PureCSharpMLKEM768.PublicKeyBytes;
    public const int CiphertextBytes = PureCSharpMLKEM768.CiphertextBytes;
    public const int SharedSecretBytes = PureCSharpMLKEM768.SharedSecretBytes;
    public const int SecretKeyBytes = PureCSharpMLKEM768.SecretKeyBytes;
    public const int KeypairSeedBytes = PureCSharpMLKEM768.KeypairSeedBytes;
    public const int EncapsulationSeedBytes = PureCSharpMLKEM768.EncapsulationSeedBytes;
    public const int IncrementalHeaderBytes = PureCSharpMLKEM768.IncrementalHeaderBytes;
    public const int EncapsulationKeyVectorBytes = PureCSharpMLKEM768.EncapsulationKeyVectorBytes;
    public const int CiphertextPart1Bytes = PureCSharpMLKEM768.CiphertextPart1Bytes;
    public const int CiphertextPart2Bytes = PureCSharpMLKEM768.CiphertextPart2Bytes;
    public const int IncrementalEncapsulationSecretBytes =
        PureCSharpMLKEM768.IncrementalEncapsulationSecretBytes;
    public const int PrivateKeyRepresentationBytes = 5 + KeypairSeedBytes + PublicKeyBytes;

    private const int EkSeedOffset = EncapsulationKeyVectorBytes;
    private const int HeaderHashOffset = EncapsulationSeedBytes;
    private static readonly byte[] MagicBytes = { 0x4b, 0x4d, 0x4c, 0x4b, 0x31 };

    public sealed class PrivateKey
    {
        private readonly byte[] _secretKey;
        private readonly byte[] _representationBytes;

        private PrivateKey(byte[] secretKey, byte[] representationBytes, PublicKey publicKey)
        {
            _secretKey = secretKey;
            _representationBytes = representationBytes;
            PublicKey = publicKey;
        }

        public PublicKey PublicKey { get; }

        public byte[] Representation => Copy(_representationBytes);

        public static PrivateKey Generate()
        {
            byte[] seed = RandomBytes(KeypairSeedBytes);
            return FromSeed(seed);
        }

        public static PrivateKey FromRepresentation(byte[] representation)
        {
            ArgumentNullException.ThrowIfNull(representation);
            if (representation.Length != PrivateKeyRepresentationBytes || !StartsWithMagic(representation))
            {
                throw new MLKemException.InvalidPrivateKeyRepresentation();
            }

            int seedStart = MagicBytes.Length;
            int publicKeyStart = seedStart + KeypairSeedBytes;
            byte[] seed = Slice(representation, seedStart, publicKeyStart);
            byte[] expectedPublicKey = Slice(representation, publicKeyStart, PrivateKeyRepresentationBytes);
            PrivateKey generated = FromSeed(seed);

            if (!PureCSharpMLKEM768.ConstantTimeCompare(generated.PublicKey.RawRepresentation, expectedPublicKey))
            {
                throw new MLKemException.InvalidPrivateKeyRepresentation();
            }

            return generated;
        }

        internal static PrivateKey FromSeedForTesting(byte[] seed)
        {
            ArgumentNullException.ThrowIfNull(seed);
            if (seed.Length != KeypairSeedBytes)
            {
                throw new MLKemException.InvalidPrivateKeyRepresentation();
            }

            return FromSeed(Copy(seed));
        }

        public byte[] Decapsulate(byte[] ciphertext)
        {
            ArgumentNullException.ThrowIfNull(ciphertext);
            if (ciphertext.Length != CiphertextBytes)
            {
                throw new MLKemException.InvalidCiphertext();
            }

            return PureCSharpMLKEM768.Decapsulate(Copy(ciphertext), _secretKey);
        }

        public byte[] DecapsulateParts(byte[] ciphertextPart1, byte[] ciphertextPart2) =>
            MLKemNative768.DecapsulateParts(this, ciphertextPart1, ciphertextPart2);

        private static PrivateKey FromSeed(byte[] seed)
        {
            if (seed.Length != KeypairSeedBytes)
            {
                throw new MLKemException.OperationFailed("Invalid ML-KEM-768 keypair seed");
            }

            (byte[] publicKey, byte[] secretKey) = PureCSharpMLKEM768.KeypairDerand(seed);
            return BuildPrivateKey(seed, publicKey, secretKey);
        }

        private static PrivateKey BuildPrivateKey(byte[] seed, byte[] publicKey, byte[] secretKey)
        {
            if (!PureCSharpMLKEM768.CheckSecretKey(secretKey))
            {
                throw new MLKemException.OperationFailed("ML-KEM-768 secret key validation failed");
            }

            var representation = new byte[PrivateKeyRepresentationBytes];
            Array.Copy(MagicBytes, 0, representation, 0, MagicBytes.Length);
            Array.Copy(seed, 0, representation, MagicBytes.Length, KeypairSeedBytes);
            Array.Copy(publicKey, 0, representation, MagicBytes.Length + KeypairSeedBytes, PublicKeyBytes);

            return new PrivateKey(Copy(secretKey), representation, new PublicKey(publicKey));
        }
    }

    public sealed class PublicKey
    {
        private readonly byte[] _rawRepresentationBytes;

        public PublicKey(byte[] rawRepresentation)
        {
            ArgumentNullException.ThrowIfNull(rawRepresentation);
            _rawRepresentationBytes = Copy(rawRepresentation);
            if (_rawRepresentationBytes.Length != PublicKeyBytes ||
                !PureCSharpMLKEM768.CheckPublicKey(_rawRepresentationBytes))
            {
                throw new MLKemException.InvalidPublicKey();
            }
        }

        public byte[] RawRepresentation => Copy(_rawRepresentationBytes);

        public Encapsulation Encapsulate()
        {
            byte[] coins = RandomBytes(EncapsulationSeedBytes);
            return EncapsulateDerand(coins);
        }

        internal Encapsulation EncapsulateDerand(byte[] coins)
        {
            ArgumentNullException.ThrowIfNull(coins);
            if (coins.Length != EncapsulationSeedBytes)
            {
                throw new MLKemException.OperationFailed("Invalid ML-KEM-768 encapsulation seed");
            }

            (byte[] ciphertext, byte[] sharedSecret) =
                PureCSharpMLKEM768.EncapsulateDerand(_rawRepresentationBytes, Copy(coins));
            return new Encapsulation(ciphertext, sharedSecret);
        }
    }

    public sealed class Encapsulation : IEquatable<Encapsulation>
    {
        private readonly byte[] _ciphertextBytes;
        private readonly byte[] _sharedSecretBytes;

        internal Encapsulation(byte[] ciphertextBytes, byte[] sharedSecretBytes)
        {
            _ciphertextBytes = Copy(ciphertextBytes);
            _sharedSecretBytes = Copy(sharedSecretBytes);
        }

        public byte[] Ciphertext => Copy(_ciphertextBytes);

        public byte[] SharedSecret => Copy(_sharedSecretBytes);

        public bool Equals(Encapsulation? other) =>
            other is not null &&
            _ciphertextBytes.SequenceEqual(other._ciphertextBytes) &&
            _sharedSecretBytes.SequenceEqual(other._sharedSecretBytes);

        public override bool Equals(object? obj) => Equals(obj as Encapsulation);

        public override int GetHashCode() =>
            HashCode.Combine(ContentHashCode(_ciphertextBytes), ContentHashCode(_sharedSecretBytes));
    }

    public sealed class IncrementalPublicKey : IEquatable<IncrementalPublicKey>
    {
        private readonly byte[] _headerBytes;
        private readonly byte[] _encapsulationKeyVectorBytes;

        public IncrementalPublicKey(byte[] header, byte[] encapsulationKeyVector)
        {
            byte[] publicKey = PublicKeyFromIncremental(header, encapsulationKeyVector);
            _headerBytes = Copy(header);
            _encapsulationKeyVectorBytes = Copy(encapsulationKeyVector);
            PublicKey = new PublicKey(publicKey);
        }

        internal IncrementalPublicKey(byte[] header, byte[] encapsulationKeyVector, PublicKey publicKey)
        {
            _headerBytes = Copy(header);
            _encapsulationKeyVectorBytes = Copy(encapsulationKeyVector);
            PublicKey = publicKey;
        }

        public byte[] Header => Copy(_headerBytes);

        public byte[] EncapsulationKeyVector => Copy(_encapsulationKeyVectorBytes);

        public PublicKey PublicKey { get; }

        public bool Equals(IncrementalPublicKey? other) =>
            other is not null &&
            _headerBytes.SequenceEqual(other._headerBytes) &&
            _encapsulationKeyVectorBytes.SequenceEqual(other._encapsulationKeyVectorBytes);

        public override bool Equals(object? obj) => Equals(obj as IncrementalPublicKey);

        public override int GetHashCode() =>
            HashCode.Combine(ContentHashCode(_headerBytes), ContentHashCode(_encapsulationKeyVectorBytes));
    }

    public sealed class IncrementalEncapsulationPart1 : IEquatable<IncrementalEncapsulationPart1>
    {
        private readonly byte[] _encapsulationSecretBytes;
        private readonly byte[] _ciphertextPart1Bytes;
        private readonly byte[] _sharedSecretBytes;

        internal IncrementalEncapsulationPart1(byte[] encapsulationSecret, byte[] ciphertextPart1, byte[] sharedSecret)
        {
            _encapsulationSecretBytes = Copy(encapsulationSecret);
            _ciphertextPart1Bytes = Copy(ciphertextPart1);
            _sharedSecretBytes = Copy(sharedSecret);
        }

        public byte[] EncapsulationSecret => Copy(_encapsulationSecretBytes);

        public byte[] EncapsSecret => EncapsulationSecret;

        public byte[] CiphertextPart1 => Copy(_ciphertextPart1Bytes);

        public byte[] SharedSecret => Copy(_sharedSecretBytes);

        public bool Equals(IncrementalEncapsulationPart1? other) =>
            other is not null &&
            _encapsulationSecretBytes.SequenceEqual(other._encapsulationSecretBytes) &&
            _ciphertextPart1Bytes.SequenceEqual(other._ciphertextPart1Bytes) &&
            _sharedSecretBytes.SequenceEqual(other._sharedSecretBytes);

        public override bool Equals(object? obj) => Equals(obj as IncrementalEncapsulationPart1);

        public override int GetHashCode() => HashCode.Combine(
            ContentHashCode(_encapsulationSecretBytes),
            ContentHashCode(_ciphertextPart1Bytes),
            ContentHashCode(_sharedSecretBytes));
    }

    public static IncrementalPublicKey PublicKeyToIncremental(PublicKey publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        return PublicKeyToIncremental(publicKey.RawRepresentation);
    }

    public static IncrementalPublicKey PublicKeyToIncremental(byte[] publicKey)
    {
        PublicKey validatedPublicKey = new(publicKey);
        byte[] rawPublicKey = validatedPublicKey.RawRepresentation;
        byte[] header = new byte[IncrementalHeaderBytes];
        Array.Copy(rawPublicKey, EkSeedOffset, header, 0, EncapsulationSeedBytes);
        Array.Copy(PureCSharpMLKEM768.Sha3256Public(rawPublicKey), 0, header, HeaderHashOffset, SharedSecretBytes);

        return new IncrementalPublicKey(
            header,
            Slice(rawPublicKey, 0, EkSeedOffset),
            validatedPublicKey);
    }

    public static byte[] PublicKeyFromIncremental(byte[] header, byte[] encapsulationKeyVector)
    {
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(encapsulationKeyVector);
        if (header.Length != IncrementalHeaderBytes)
        {
            throw new MLKemException.InvalidIncrementalHeader();
        }
        if (encapsulationKeyVector.Length != EncapsulationKeyVectorBytes)
        {
            throw new MLKemException.InvalidEncapsulationKeyVector();
        }

        var publicKey = new byte[PublicKeyBytes];
        Array.Copy(encapsulationKeyVector, 0, publicKey, 0, EncapsulationKeyVectorBytes);
        Array.Copy(header, 0, publicKey, EkSeedOffset, EncapsulationSeedBytes);

        byte[] expectedHash = PureCSharpMLKEM768.Sha3256Public(publicKey);
        byte[] headerHash = Slice(header, HeaderHashOffset, IncrementalHeaderBytes);
        if (!PureCSharpMLKEM768.ConstantTimeCompare(expectedHash, headerHash))
        {
            throw new MLKemException.InvalidIncrementalHeader("Invalid ML-KEM-768 incremental header hash");
        }

        if (!PureCSharpMLKEM768.CheckPublicKey(publicKey))
        {
            throw new MLKemException.InvalidPublicKey();
        }

        return publicKey;
    }

    public static IncrementalEncapsulationPart1 EncapsulatePart1(byte[] header, byte[]? randomness = null)
    {
        ArgumentNullException.ThrowIfNull(header);
        if (header.Length != IncrementalHeaderBytes)
        {
            throw new MLKemException.InvalidIncrementalHeader();
        }

        byte[] coins = randomness is null ? RandomBytes(EncapsulationSeedBytes) : Copy(randomness);
        if (coins.Length != EncapsulationSeedBytes)
        {
            throw new MLKemException.OperationFailed("Invalid ML-KEM-768 encapsulation randomness");
        }

        PureCSharpMLKEM768.IncrementalEncapsulationResult output =
            PureCSharpMLKEM768.EncapsulatePart1Derand(Copy(header), coins);

        return new IncrementalEncapsulationPart1(
            output.EncapsulationSecret,
            output.CiphertextPart1,
            output.SharedSecret);
    }

    public static byte[] EncapsulatePart2(
        byte[] encapsSecret,
        byte[] header,
        byte[] encapsulationKeyVector)
    {
        ArgumentNullException.ThrowIfNull(encapsSecret);
        if (encapsSecret.Length != IncrementalEncapsulationSecretBytes)
        {
            throw new MLKemException.InvalidIncrementalEncapsulationSecret();
        }

        byte[] publicKey = PublicKeyFromIncremental(header, encapsulationKeyVector);
        return PureCSharpMLKEM768.EncapsulatePart2(Copy(encapsSecret), publicKey);
    }

    public static byte[] DecapsulateParts(
        PrivateKey privateKey,
        byte[] ciphertextPart1,
        byte[] ciphertextPart2)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(ciphertextPart1);
        ArgumentNullException.ThrowIfNull(ciphertextPart2);
        if (ciphertextPart1.Length != CiphertextPart1Bytes)
        {
            throw new MLKemException.InvalidCiphertext("Invalid ML-KEM-768 ciphertext part1");
        }
        if (ciphertextPart2.Length != CiphertextPart2Bytes)
        {
            throw new MLKemException.InvalidCiphertext("Invalid ML-KEM-768 ciphertext part2");
        }

        var ciphertext = new byte[CiphertextBytes];
        Array.Copy(ciphertextPart1, 0, ciphertext, 0, CiphertextPart1Bytes);
        Array.Copy(ciphertextPart2, 0, ciphertext, CiphertextPart1Bytes, CiphertextPart2Bytes);
        return privateKey.Decapsulate(ciphertext);
    }

    internal static (byte[] PublicKey, byte[] SecretKey) KeypairDerandForTesting(byte[] seed)
    {
        ArgumentNullException.ThrowIfNull(seed);
        (byte[] publicKey, byte[] secretKey) = PureCSharpMLKEM768.KeypairDerand(Copy(seed));
        return (publicKey, secretKey);
    }

    internal static Encapsulation EncapsulateDerandForTesting(byte[] publicKey, byte[] coins) =>
        new PublicKey(publicKey).EncapsulateDerand(coins);

    private static byte[] RandomBytes(int count)
    {
        var output = new byte[count];
        try
        {
            RandomNumberGenerator.Fill(output);
        }
        catch (Exception exception)
        {
            throw new MLKemException.RandomGenerationFailed(exception);
        }

        return output;
    }

    private static bool StartsWithMagic(byte[] bytes)
    {
        if (bytes.Length < MagicBytes.Length)
        {
            return false;
        }

        for (int i = 0; i < MagicBytes.Length; i++)
        {
            if (bytes[i] != MagicBytes[i])
            {
                return false;
            }
        }

        return true;
    }

    private static byte[] Copy(byte[] source)
    {
        var result = new byte[source.Length];
        Array.Copy(source, result, source.Length);
        return result;
    }

    private static byte[] Slice(byte[] source, int start, int end)
    {
        var result = new byte[end - start];
        Array.Copy(source, start, result, 0, end - start);
        return result;
    }

    private static int ContentHashCode(byte[] bytes)
    {
        var hash = new HashCode();
        foreach (byte value in bytes)
        {
            hash.Add(value);
        }

        return hash.ToHashCode();
    }
}
