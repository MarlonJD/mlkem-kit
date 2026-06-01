namespace MLKemNative;

/// <summary>
/// Pure managed ML-KEM-768 (FIPS 203) primitive: deterministic key derivation,
/// encapsulation/decapsulation with implicit rejection, and the ML-KEM Braid
/// incremental helpers.
/// </summary>
/// <remarks>
/// Ported from <c>platforms/swift/.../PureSwiftMLKEM768.swift</c> and
/// cross-checked against <c>platforms/android/.../PureKotlinMLKEM768.kt</c>.
/// Coefficients are stored as <see cref="short"/> (matching the Swift
/// <c>Int16</c> widths); every arithmetic step widens to <see cref="int"/> and
/// truncates back exactly as the Swift reference does. This and
/// <see cref="Keccak"/> are the only hand-rolled cryptography in the package.
/// </remarks>
internal static class PureCSharpMLKEM768
{
    internal const int PublicKeyBytes = 1184;
    internal const int CiphertextBytes = 1088;
    internal const int SharedSecretBytes = 32;
    internal const int SecretKeyBytes = 2400;
    internal const int KeypairSeedBytes = 64;
    internal const int EncapsulationSeedBytes = 32;
    internal const int IncrementalHeaderBytes = 64;
    internal const int EncapsulationKeyVectorBytes = 1152;
    internal const int CiphertextPart1Bytes = 960;
    internal const int CiphertextPart2Bytes = 128;
    internal const int IncrementalEncapsulationSecretBytes = 64;

    private const int N = 256;
    private const int K = 3;
    private const int Q = 3329;
    private const int SymBytes = 32;
    private const int PolyBytes = 384;
    private const int PolyVecBytes = 1152;
    private const int Eta1 = 2;
    private const int Eta2 = 2;
    private const int PolyCompressedBytesDU = 320;
    private const int PolyVecCompressedBytesDU = 960;
    private const int PolyCompressedBytesDV = 128;
    private const int XofRate = 168;

    internal sealed class IncrementalEncapsulationResult
    {
        internal IncrementalEncapsulationResult(byte[] encapsulationSecret, byte[] ciphertextPart1, byte[] sharedSecret)
        {
            EncapsulationSecret = encapsulationSecret;
            CiphertextPart1 = ciphertextPart1;
            SharedSecret = sharedSecret;
        }

        internal byte[] EncapsulationSecret { get; }

        internal byte[] CiphertextPart1 { get; }

        internal byte[] SharedSecret { get; }
    }

    internal static (byte[] PublicKey, byte[] SecretKey) KeypairDerand(byte[] seed)
    {
        if (seed.Length != KeypairSeedBytes)
        {
            throw new MLKemException.InvalidPrivateKeyRepresentation();
        }

        var pk = new byte[PublicKeyBytes];
        var sk = new byte[SecretKeyBytes];
        (byte[] indcpaPk, byte[] indcpaSk) = IndcpaKeypairDerand(seed);
        Array.Copy(indcpaPk, 0, pk, 0, PublicKeyBytes);
        Array.Copy(indcpaSk, 0, sk, 0, PolyVecBytes);
        Array.Copy(pk, 0, sk, PolyVecBytes, PublicKeyBytes);
        Array.Copy(Sha3256(pk), 0, sk, SecretKeyBytes - 64, 32);
        Array.Copy(seed, 32, sk, SecretKeyBytes - 32, 32);
        return (pk, sk);
    }

    internal static (byte[] Ciphertext, byte[] SharedSecret) EncapsulateDerand(byte[] publicKey, byte[] seed)
    {
        if (publicKey.Length != PublicKeyBytes || !CheckPublicKey(publicKey))
        {
            throw new MLKemException.InvalidPublicKey();
        }
        if (seed.Length != EncapsulationSeedBytes)
        {
            throw new MLKemException.OperationFailed("Invalid ML-KEM-768 encapsulation seed");
        }

        byte[] buf = Concat(seed, Sha3256(publicKey));
        byte[] kr = Sha3512(buf);
        byte[] ct = IndcpaEnc(Slice(buf, 0, 32), publicKey, Slice(kr, 32, 64));
        return (ct, Slice(kr, 0, 32));
    }

    internal static byte[] Decapsulate(byte[] ciphertext, byte[] secretKey)
    {
        if (ciphertext.Length != CiphertextBytes)
        {
            throw new MLKemException.InvalidCiphertext();
        }
        if (secretKey.Length != SecretKeyBytes || !CheckSecretKey(secretKey))
        {
            throw new MLKemException.InvalidPrivateKeyRepresentation();
        }

        byte[] buf = Concat(
            IndcpaDec(ciphertext, Slice(secretKey, 0, PolyVecBytes)),
            Slice(secretKey, SecretKeyBytes - 64, SecretKeyBytes - 32));
        byte[] kr = Sha3512(buf);
        byte[] pk = Slice(secretKey, PolyVecBytes, PolyVecBytes + PublicKeyBytes);
        byte[] cmp = IndcpaEnc(Slice(buf, 0, 32), pk, Slice(kr, 32, 64));
        bool fail = !ConstantTimeCompare(ciphertext, cmp);

        byte[] rejectionInput = Concat(Slice(secretKey, SecretKeyBytes - 32, SecretKeyBytes), ciphertext);
        byte[] ss = Shake256(rejectionInput, 32);
        int mask = fail ? 0 : 0xff;
        for (int i = 0; i < 32; i++)
        {
            ss[i] = (byte)((ss[i] & (~mask & 0xff)) | (kr[i] & mask));
        }
        return ss;
    }

    internal static bool CheckPublicKey(byte[] publicKey)
    {
        if (publicKey.Length != PublicKeyBytes)
        {
            return false;
        }
        PolyVec pv = PolyVecFromBytes(Slice(publicKey, 0, PolyVecBytes));
        PolyVecReduce(pv);
        return ConstantTimeCompare(Slice(publicKey, 0, PolyVecBytes), PolyVecToBytes(pv));
    }

    internal static bool CheckSecretKey(byte[] secretKey)
    {
        if (secretKey.Length != SecretKeyBytes)
        {
            return false;
        }
        byte[] pk = Slice(secretKey, PolyVecBytes, PolyVecBytes + PublicKeyBytes);
        byte[] h = Sha3256(pk);
        return ConstantTimeCompare(Slice(secretKey, SecretKeyBytes - 64, SecretKeyBytes - 32), h);
    }

    internal static (byte[] Header, byte[] Vector) PublicKeyToIncremental(byte[] publicKey)
    {
        if (publicKey.Length != PublicKeyBytes || !CheckPublicKey(publicKey))
        {
            throw new MLKemException.InvalidPublicKey();
        }
        byte[] vector = Slice(publicKey, 0, EncapsulationKeyVectorBytes);
        byte[] seed = Slice(publicKey, EncapsulationKeyVectorBytes, PublicKeyBytes);
        return (Concat(seed, Sha3256(publicKey)), vector);
    }

    internal static byte[] PublicKeyFromIncremental(byte[] header, byte[] vector)
    {
        if (header.Length != IncrementalHeaderBytes || vector.Length != EncapsulationKeyVectorBytes)
        {
            throw new MLKemException.InvalidPublicKey();
        }

        byte[] pk = Concat(vector, Slice(header, 0, 32));
        byte[] expectedHash = Sha3256(pk);
        if (!ConstantTimeCompare(expectedHash, Slice(header, 32, 64)) || !CheckPublicKey(pk))
        {
            throw new MLKemException.InvalidPublicKey();
        }
        return pk;
    }

    internal static IncrementalEncapsulationResult EncapsulatePart1Derand(byte[] header, byte[] seed)
    {
        if (header.Length != IncrementalHeaderBytes)
        {
            throw new MLKemException.InvalidPublicKey();
        }
        if (seed.Length != EncapsulationSeedBytes)
        {
            throw new MLKemException.OperationFailed("Invalid ML-KEM-768 encapsulation seed");
        }

        byte[] encapsulationSecret = Concat(seed, Slice(header, 32, 64));
        byte[] kr = Sha3512(encapsulationSecret);
        byte[] sharedSecret = Slice(kr, 0, 32);
        Array.Copy(kr, 32, encapsulationSecret, 32, 32);

        var dummyPublicKey = new byte[PublicKeyBytes];
        Array.Copy(header, 0, dummyPublicKey, EncapsulationKeyVectorBytes, 32);
        byte[] ct = IndcpaEnc(Slice(encapsulationSecret, 0, 32), dummyPublicKey, Slice(encapsulationSecret, 32, 64));
        return new IncrementalEncapsulationResult(
            encapsulationSecret,
            Slice(ct, 0, CiphertextPart1Bytes),
            sharedSecret);
    }

    internal static byte[] EncapsulatePart2(byte[] encapsulationSecret, byte[] header, byte[] vector)
    {
        byte[] publicKey = PublicKeyFromIncremental(header, vector);
        return EncapsulatePart2(encapsulationSecret, publicKey);
    }

    internal static byte[] EncapsulatePart2(byte[] encapsulationSecret, byte[] publicKey)
    {
        if (encapsulationSecret.Length != IncrementalEncapsulationSecretBytes)
        {
            throw new MLKemException.InvalidIncrementalEncapsulationSecret();
        }
        if (publicKey.Length != PublicKeyBytes || !CheckPublicKey(publicKey))
        {
            throw new MLKemException.InvalidPublicKey();
        }

        byte[] ct = IndcpaEnc(Slice(encapsulationSecret, 0, 32), publicKey, Slice(encapsulationSecret, 32, 64));
        return Slice(ct, CiphertextPart1Bytes, CiphertextBytes);
    }

    internal static byte[] DecapsulateParts(byte[] ciphertextPart1, byte[] ciphertextPart2, byte[] secretKey)
    {
        if (ciphertextPart1.Length != CiphertextPart1Bytes || ciphertextPart2.Length != CiphertextPart2Bytes)
        {
            throw new MLKemException.InvalidCiphertext();
        }
        return Decapsulate(Concat(ciphertextPart1, ciphertextPart2), secretKey);
    }

    internal static byte[] Sha3256Public(byte[] input) => Sha3256(input);

    // MARK: - INDCPA

    private static (byte[] PublicKey, byte[] SecretKey) IndcpaKeypairDerand(byte[] seed64)
    {
        byte[] seedWithDomain = Concat(Slice(seed64, 0, 32), new byte[] { K });
        byte[] hashed = Sha3512(seedWithDomain);
        byte[] publicSeed = Slice(hashed, 0, 32);
        byte[] noiseSeed = Slice(hashed, 32, 64);
        PolyVec[] matrix = GenMatrix(publicSeed, transposed: false);

        var skpv = new PolyVec();
        var e = new PolyVec();
        for (int i = 0; i < K; i++)
        {
            skpv.Vec[i] = GetNoise(Eta1, noiseSeed, i);
            e.Vec[i] = GetNoise(Eta1, noiseSeed, i + K);
        }

        PolyVecNtt(skpv);
        PolyVecNtt(e);
        PolyVecMulcache skpvCache = PolyVecMulcacheCompute(skpv);
        var pkpv = new PolyVec();
        for (int i = 0; i < K; i++)
        {
            pkpv.Vec[i] = PolyVecBaseMulAcc(matrix[i], skpv, skpvCache);
        }
        PolyVecToMont(pkpv);
        PolyVecAdd(pkpv, e);
        PolyVecReduce(pkpv);
        PolyVecReduce(skpv);

        return (Concat(PolyVecToBytes(pkpv), publicSeed), PolyVecToBytes(skpv));
    }

    private static byte[] IndcpaEnc(byte[] message, byte[] publicKey, byte[] coins)
    {
        PolyVec pkpv = PolyVecFromBytes(Slice(publicKey, 0, PolyVecBytes));
        byte[] seed = Slice(publicKey, PolyVecBytes, PublicKeyBytes);
        Poly kpoly = PolyFromMessage(message);
        PolyVec[] at = GenMatrix(seed, transposed: true);

        var sp = new PolyVec();
        var ep = new PolyVec();
        for (int i = 0; i < K; i++)
        {
            sp.Vec[i] = GetNoise(Eta1, coins, i);
            ep.Vec[i] = GetNoise(Eta2, coins, i + K);
        }
        Poly epp = GetNoise(Eta2, coins, 2 * K);

        PolyVecNtt(sp);
        PolyVecMulcache spCache = PolyVecMulcacheCompute(sp);
        var b = new PolyVec();
        for (int i = 0; i < K; i++)
        {
            b.Vec[i] = PolyVecBaseMulAcc(at[i], sp, spCache);
        }
        Poly v = PolyVecBaseMulAcc(pkpv, sp, spCache);

        PolyVecInvNtt(b);
        PolyInvNtt(v);
        PolyVecAdd(b, ep);
        PolyAdd(v, epp);
        PolyAdd(v, kpoly);
        PolyVecReduce(b);
        PolyReduce(v);
        return PackCiphertext(b, v);
    }

    private static byte[] IndcpaDec(byte[] ciphertext, byte[] secretKey)
    {
        (PolyVec b, Poly v) = UnpackCiphertext(ciphertext);
        PolyVec skpv = PolyVecFromBytes(secretKey);
        PolyVecNtt(b);
        PolyVecMulcache bCache = PolyVecMulcacheCompute(b);
        Poly sb = PolyVecBaseMulAcc(skpv, b, bCache);
        PolyInvNtt(sb);
        PolySub(v, sb);
        PolyReduce(v);
        return PolyToMessage(v);
    }

    // MARK: - Polynomial types

    private sealed class Poly
    {
        internal short[] Coeffs { get; } = new short[N];
    }

    private sealed class PolyVec
    {
        internal Poly[] Vec { get; } = CreatePolys(K);
    }

    private sealed class PolyMulcache
    {
        internal short[] Coeffs { get; } = new short[N / 2];
    }

    private sealed class PolyVecMulcache
    {
        internal PolyMulcache[] Vec { get; } = CreateMulcaches(K);
    }

    private static Poly[] CreatePolys(int count)
    {
        var result = new Poly[count];
        for (int i = 0; i < count; i++)
        {
            result[i] = new Poly();
        }
        return result;
    }

    private static PolyMulcache[] CreateMulcaches(int count)
    {
        var result = new PolyMulcache[count];
        for (int i = 0; i < count; i++)
        {
            result[i] = new PolyMulcache();
        }
        return result;
    }

    // MARK: - Ciphertext packing

    private static byte[] PackCiphertext(PolyVec b, Poly v) => Concat(PolyVecCompressDU(b), PolyCompressDV(v));

    private static (PolyVec B, Poly V) UnpackCiphertext(byte[] c) =>
        (PolyVecDecompressDU(Slice(c, 0, PolyVecCompressedBytesDU)),
         PolyDecompressDV(Slice(c, PolyVecCompressedBytesDU, CiphertextBytes)));

    // MARK: - Matrix and sampling

    private static PolyVec[] GenMatrix(byte[] seed, bool transposed)
    {
        var matrix = new PolyVec[K];
        for (int row = 0; row < K; row++)
        {
            matrix[row] = new PolyVec();
            for (int col = 0; col < K; col++)
            {
                byte[] suffix = transposed
                    ? new[] { (byte)row, (byte)col }
                    : new[] { (byte)col, (byte)row };
                matrix[row].Vec[col] = RejUniformPoly(Concat(seed, suffix));
            }
        }
        return matrix;
    }

    private static Poly RejUniformPoly(byte[] seed)
    {
        var xof = new Shake128Xof(seed);
        var output = new Poly();
        int ctr = 0;
        byte[] buffer = xof.SqueezeBlocks(3);
        ctr = RejUniform(output.Coeffs, N, ctr, buffer);
        while (ctr < N)
        {
            buffer = xof.SqueezeBlocks(1);
            ctr = RejUniform(output.Coeffs, N, ctr, buffer);
        }
        return output;
    }

    private static int RejUniform(short[] r, int target, int offset, byte[] buffer)
    {
        int ctr = offset;
        int pos = 0;
        while (ctr < target && pos + 3 <= buffer.Length)
        {
            int val0 = (buffer[pos] | (buffer[pos + 1] << 8)) & 0x0fff;
            int val1 = ((buffer[pos + 1] >> 4) | (buffer[pos + 2] << 4)) & 0x0fff;
            pos += 3;
            if (val0 < Q)
            {
                r[ctr] = (short)val0;
                ctr++;
            }
            if (ctr < target && val1 < Q)
            {
                r[ctr] = (short)val1;
                ctr++;
            }
        }
        return ctr;
    }

    private static Poly GetNoise(int eta, byte[] seed, int nonce)
    {
        byte[] bytes = Shake256(Concat(seed, new[] { (byte)nonce }), eta * N / 4);
        return Cbd2(bytes);
    }

    private static Poly Cbd2(byte[] buffer)
    {
        var r = new Poly();
        for (int i = 0; i < N / 8; i++)
        {
            uint t = Load32(buffer, 4 * i);
            uint d = t & 0x55555555u;
            d += (t >> 1) & 0x55555555u;
            for (int j = 0; j < 8; j++)
            {
                int a = (int)((d >> (4 * j)) & 0x3);
                int b = (int)((d >> (4 * j + 2)) & 0x3);
                r.Coeffs[8 * i + j] = (short)(a - b);
            }
        }
        return r;
    }

    private static uint Load32(byte[] bytes, int offset) =>
        bytes[offset]
        | ((uint)bytes[offset + 1] << 8)
        | ((uint)bytes[offset + 2] << 16)
        | ((uint)bytes[offset + 3] << 24);

    // MARK: - Compression

    private static byte[] PolyVecCompressDU(PolyVec a)
    {
        var output = new byte[PolyVecCompressedBytesDU];
        for (int i = 0; i < K; i++)
        {
            Array.Copy(PolyCompressDU(a.Vec[i]), 0, output, i * PolyCompressedBytesDU, PolyCompressedBytesDU);
        }
        return output;
    }

    private static PolyVec PolyVecDecompressDU(byte[] bytes)
    {
        var output = new PolyVec();
        for (int i = 0; i < K; i++)
        {
            output.Vec[i] = PolyDecompressDU(Slice(bytes, i * PolyCompressedBytesDU, (i + 1) * PolyCompressedBytesDU));
        }
        return output;
    }

    private static byte[] PolyCompressDU(Poly a)
    {
        var r = new byte[PolyCompressedBytesDU];
        for (int j = 0; j < N / 4; j++)
        {
            int t0 = ScalarCompressD10(a.Coeffs[4 * j + 0]);
            int t1 = ScalarCompressD10(a.Coeffs[4 * j + 1]);
            int t2 = ScalarCompressD10(a.Coeffs[4 * j + 2]);
            int t3 = ScalarCompressD10(a.Coeffs[4 * j + 3]);
            r[5 * j + 0] = (byte)t0;
            r[5 * j + 1] = (byte)((t0 >> 8) | ((t1 << 2) & 0xff));
            r[5 * j + 2] = (byte)((t1 >> 6) | ((t2 << 4) & 0xff));
            r[5 * j + 3] = (byte)((t2 >> 4) | ((t3 << 6) & 0xff));
            r[5 * j + 4] = (byte)(t3 >> 2);
        }
        return r;
    }

    private static Poly PolyDecompressDU(byte[] bytes)
    {
        var r = new Poly();
        for (int j = 0; j < N / 4; j++)
        {
            int @base = 5 * j;
            int t0 = bytes[@base] | (bytes[@base + 1] << 8);
            int t1 = (bytes[@base + 1] >> 2) | (bytes[@base + 2] << 6);
            int t2 = (bytes[@base + 2] >> 4) | (bytes[@base + 3] << 4);
            int t3 = (bytes[@base + 3] >> 6) | (bytes[@base + 4] << 2);
            r.Coeffs[4 * j + 0] = ScalarDecompressD10(t0 & 0x03ff);
            r.Coeffs[4 * j + 1] = ScalarDecompressD10(t1 & 0x03ff);
            r.Coeffs[4 * j + 2] = ScalarDecompressD10(t2 & 0x03ff);
            r.Coeffs[4 * j + 3] = ScalarDecompressD10(t3 & 0x03ff);
        }
        return r;
    }

    private static byte[] PolyCompressDV(Poly a)
    {
        var r = new byte[PolyCompressedBytesDV];
        for (int i = 0; i < N / 8; i++)
        {
            int t0 = ScalarCompressD4(a.Coeffs[8 * i + 0]);
            int t1 = ScalarCompressD4(a.Coeffs[8 * i + 1]);
            int t2 = ScalarCompressD4(a.Coeffs[8 * i + 2]);
            int t3 = ScalarCompressD4(a.Coeffs[8 * i + 3]);
            int t4 = ScalarCompressD4(a.Coeffs[8 * i + 4]);
            int t5 = ScalarCompressD4(a.Coeffs[8 * i + 5]);
            int t6 = ScalarCompressD4(a.Coeffs[8 * i + 6]);
            int t7 = ScalarCompressD4(a.Coeffs[8 * i + 7]);
            r[4 * i + 0] = (byte)(t0 | (t1 << 4));
            r[4 * i + 1] = (byte)(t2 | (t3 << 4));
            r[4 * i + 2] = (byte)(t4 | (t5 << 4));
            r[4 * i + 3] = (byte)(t6 | (t7 << 4));
        }
        return r;
    }

    private static Poly PolyDecompressDV(byte[] bytes)
    {
        var r = new Poly();
        for (int i = 0; i < N / 2; i++)
        {
            r.Coeffs[2 * i + 0] = ScalarDecompressD4(bytes[i] & 0x0f);
            r.Coeffs[2 * i + 1] = ScalarDecompressD4((bytes[i] >> 4) & 0x0f);
        }
        return r;
    }

    private static int ScalarCompressD1(short u)
    {
        uint d0 = (uint)(ushort)u * 1290168u;
        return (int)((d0 + (1u << 30)) >> 31);
    }

    private static int ScalarCompressD4(short u)
    {
        uint d0 = (uint)(ushort)u * 1290160u;
        return (int)((d0 + (1u << 27)) >> 28);
    }

    private static short ScalarDecompressD4(int u) => (short)(((u * Q) + 8) >> 4);

    private static int ScalarCompressD10(short u)
    {
        ulong d0 = (ulong)(ushort)u * 2642263040UL;
        d0 = (d0 + (1UL << 32)) >> 33;
        return (int)(d0 & 0x03ff);
    }

    private static short ScalarDecompressD10(int u) => (short)(((u * Q) + 512) >> 10);

    // MARK: - Byte (de)serialization

    private static byte[] PolyVecToBytes(PolyVec a)
    {
        var output = new byte[PolyVecBytes];
        for (int i = 0; i < K; i++)
        {
            Array.Copy(PolyToBytes(a.Vec[i]), 0, output, i * PolyBytes, PolyBytes);
        }
        return output;
    }

    private static PolyVec PolyVecFromBytes(byte[] bytes)
    {
        var r = new PolyVec();
        for (int i = 0; i < K; i++)
        {
            r.Vec[i] = PolyFromBytes(Slice(bytes, i * PolyBytes, (i + 1) * PolyBytes));
        }
        return r;
    }

    private static byte[] PolyToBytes(Poly a)
    {
        var r = new byte[PolyBytes];
        for (int i = 0; i < N / 2; i++)
        {
            int t0 = (ushort)a.Coeffs[2 * i];
            int t1 = (ushort)a.Coeffs[2 * i + 1];
            r[3 * i + 0] = (byte)t0;
            r[3 * i + 1] = (byte)((t0 >> 8) | (t1 << 4));
            r[3 * i + 2] = (byte)(t1 >> 4);
        }
        return r;
    }

    private static Poly PolyFromBytes(byte[] bytes)
    {
        var r = new Poly();
        for (int i = 0; i < N / 2; i++)
        {
            int b0 = bytes[3 * i];
            int b1 = bytes[3 * i + 1];
            int b2 = bytes[3 * i + 2];
            r.Coeffs[2 * i + 0] = (short)((b0 | (b1 << 8)) & 0x0fff);
            r.Coeffs[2 * i + 1] = (short)(((b1 >> 4) | (b2 << 4)) & 0x0fff);
        }
        return r;
    }

    private static Poly PolyFromMessage(byte[] message)
    {
        var r = new Poly();
        for (int i = 0; i < 32; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                int bit = (message[i] >> j) & 1;
                r.Coeffs[8 * i + j] = (short)(bit == 1 ? 1665 : 0);
            }
        }
        return r;
    }

    private static byte[] PolyToMessage(Poly a)
    {
        var msg = new byte[32];
        for (int i = 0; i < 32; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                msg[i] = (byte)(msg[i] | (ScalarCompressD1(a.Coeffs[8 * i + j]) << j));
            }
        }
        return msg;
    }

    // MARK: - NTT and arithmetic

    private static void PolyVecNtt(PolyVec v)
    {
        for (int i = 0; i < K; i++)
        {
            PolyNtt(v.Vec[i]);
        }
    }

    private static void PolyVecInvNtt(PolyVec v)
    {
        for (int i = 0; i < K; i++)
        {
            PolyInvNtt(v.Vec[i]);
        }
    }

    private static void PolyVecToMont(PolyVec v)
    {
        for (int i = 0; i < K; i++)
        {
            PolyToMont(v.Vec[i]);
        }
    }

    private static void PolyVecReduce(PolyVec v)
    {
        for (int i = 0; i < K; i++)
        {
            PolyReduce(v.Vec[i]);
        }
    }

    private static void PolyVecAdd(PolyVec v, PolyVec b)
    {
        for (int i = 0; i < K; i++)
        {
            PolyAdd(v.Vec[i], b.Vec[i]);
        }
    }

    private static void PolyAdd(Poly r, Poly b)
    {
        for (int i = 0; i < N; i++)
        {
            r.Coeffs[i] = (short)(r.Coeffs[i] + b.Coeffs[i]);
        }
    }

    private static void PolySub(Poly r, Poly b)
    {
        for (int i = 0; i < N; i++)
        {
            r.Coeffs[i] = (short)(r.Coeffs[i] - b.Coeffs[i]);
        }
    }

    private static void PolyReduce(Poly r)
    {
        for (int i = 0; i < N; i++)
        {
            short t = BarrettReduce(r.Coeffs[i]);
            r.Coeffs[i] = t < 0 ? (short)(t + Q) : t;
        }
    }

    private static void PolyToMont(Poly r)
    {
        for (int i = 0; i < N; i++)
        {
            r.Coeffs[i] = Fqmul(r.Coeffs[i], 1353);
        }
    }

    private static void PolyNtt(Poly p)
    {
        for (int layer = 1; layer <= 7; layer++)
        {
            int zetaIndex = 1 << (layer - 1);
            int len = N >> layer;
            int start = 0;
            while (start < N)
            {
                short zeta = Zetas[zetaIndex];
                zetaIndex++;
                for (int j = start; j < start + len; j++)
                {
                    short t = Fqmul(p.Coeffs[j + len], zeta);
                    p.Coeffs[j + len] = (short)(p.Coeffs[j] - t);
                    p.Coeffs[j] = (short)(p.Coeffs[j] + t);
                }
                start += 2 * len;
            }
        }
    }

    private static void PolyInvNtt(Poly p)
    {
        for (int j = 0; j < N; j++)
        {
            p.Coeffs[j] = Fqmul(p.Coeffs[j], 1441);
        }
        for (int layer = 7; layer >= 1; layer--)
        {
            int len = N >> layer;
            int zetaIndex = (1 << layer) - 1;
            int start = 0;
            while (start < N)
            {
                short zeta = Zetas[zetaIndex];
                zetaIndex--;
                for (int j = start; j < start + len; j++)
                {
                    short t = p.Coeffs[j];
                    p.Coeffs[j] = BarrettReduce((short)(t + p.Coeffs[j + len]));
                    p.Coeffs[j + len] = (short)(p.Coeffs[j + len] - t);
                    p.Coeffs[j + len] = Fqmul(p.Coeffs[j + len], zeta);
                }
                start += 2 * len;
            }
        }
    }

    private static PolyVecMulcache PolyVecMulcacheCompute(PolyVec v)
    {
        var cache = new PolyVecMulcache();
        for (int i = 0; i < K; i++)
        {
            cache.Vec[i] = PolyMulcacheCompute(v.Vec[i]);
        }
        return cache;
    }

    private static PolyMulcache PolyMulcacheCompute(Poly a)
    {
        var cache = new PolyMulcache();
        for (int i = 0; i < N / 4; i++)
        {
            cache.Coeffs[2 * i + 0] = Fqmul(a.Coeffs[4 * i + 1], Zetas[64 + i]);
            cache.Coeffs[2 * i + 1] = Fqmul(a.Coeffs[4 * i + 3], -Zetas[64 + i]);
        }
        return cache;
    }

    private static Poly PolyVecBaseMulAcc(PolyVec a, PolyVec b, PolyVecMulcache bCache)
    {
        var r = new Poly();
        for (int i = 0; i < N / 2; i++)
        {
            int t0 = 0;
            int t1 = 0;
            for (int j = 0; j < K; j++)
            {
                t0 += a.Vec[j].Coeffs[2 * i + 1] * bCache.Vec[j].Coeffs[i];
                t0 += a.Vec[j].Coeffs[2 * i] * b.Vec[j].Coeffs[2 * i];
                t1 += a.Vec[j].Coeffs[2 * i] * b.Vec[j].Coeffs[2 * i + 1];
                t1 += a.Vec[j].Coeffs[2 * i + 1] * b.Vec[j].Coeffs[2 * i];
            }
            r.Coeffs[2 * i] = MontgomeryReduce(t0);
            r.Coeffs[2 * i + 1] = MontgomeryReduce(t1);
        }
        return r;
    }

    private static short Fqmul(int a, int b) => MontgomeryReduce(a * b);

    private static short MontgomeryReduce(int a)
    {
        ushort aReduced = (ushort)a;
        ushort aInverted = (ushort)(aReduced * 62209);
        short t = (short)aInverted;
        int r = (a - t * Q) >> 16;
        return (short)r;
    }

    private static short BarrettReduce(short a)
    {
        int t = (20159 * a + (1 << 25)) >> 26;
        return (short)(a - t * Q);
    }

    // MARK: - Helpers

    internal static bool ConstantTimeCompare(byte[] lhs, byte[] rhs)
    {
        if (lhs.Length != rhs.Length)
        {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < lhs.Length; i++)
        {
            diff |= lhs[i] ^ rhs[i];
        }
        return diff == 0;
    }

    private static byte[] Sha3256(byte[] input) => Keccak.Sha3256(input);

    private static byte[] Sha3512(byte[] input) => Keccak.Sha3512(input);

    private static byte[] Shake256(byte[] input, int outputByteCount) => Keccak.Shake256(input, outputByteCount);

    private static byte[] Slice(byte[] source, int start, int end)
    {
        var result = new byte[end - start];
        Array.Copy(source, start, result, 0, end - start);
        return result;
    }

    private static byte[] Concat(byte[] first, byte[] second)
    {
        var result = new byte[first.Length + second.Length];
        Array.Copy(first, 0, result, 0, first.Length);
        Array.Copy(second, 0, result, first.Length, second.Length);
        return result;
    }

    private static readonly short[] Zetas =
    {
        -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577,
        182, 962, -1202, -1474, 1468, 573, -1325, 264, 383, -829, 1458,
        -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571, 1223,
        652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666,
        -1618, -1162, 126, 1469, -853, -90, -271, 830, 107, -1421, -247,
        -951, -398, 961, -1508, -725, 448, -1065, 677, -1275, -1103, 430,
        555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291,
        -460, 1574, 1653, -246, 778, 1159, -147, -777, 1483, -602, 1119,
        -1590, 644, -872, 349, 418, 329, -156, -75, 817, 1097, 603,
        610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220,
        -1187, -1659, -1185, -1530, -1278, 794, -1510, -854, -870, 478, -108,
        -308, 996, 991, 958, -1460, 1522, 1628,
    };
}
