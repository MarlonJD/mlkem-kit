namespace MLKemNative;

/// <summary>
/// Pure managed Keccak-f[1600] permutation with SHA3-256/512 and SHAKE128/256.
/// </summary>
/// <remarks>
/// This file, together with <see cref="PureCSharpMLKEM768"/>, is the only
/// hand-rolled cryptography in the package — exactly the same exception the pure
/// Swift and pure Kotlin implementations make. Everything else (AES, SHA-256,
/// HMAC, RNG) defers to the BCL. The layout mirrors the Swift/Kotlin
/// <c>Keccak</c> helpers so the four ports stay easy to diff.
/// </remarks>
internal static class Keccak
{
    private const int Sha3256Rate = 136;
    private const int Sha3512Rate = 72;
    private const int Shake128Rate = 168;
    private const int Shake256Rate = 136;

    private const byte Sha3Domain = 0x06;
    private const byte ShakeDomain = 0x1f;

    internal static byte[] Sha3256(byte[] input) => Hash(input, 32, Sha3256Rate, Sha3Domain);

    internal static byte[] Sha3512(byte[] input) => Hash(input, 64, Sha3512Rate, Sha3Domain);

    internal static byte[] Shake128(byte[] input, int outputByteCount) =>
        Hash(input, outputByteCount, Shake128Rate, ShakeDomain);

    internal static byte[] Shake256(byte[] input, int outputByteCount) =>
        Hash(input, outputByteCount, Shake256Rate, ShakeDomain);

    internal static byte[] Hash(byte[] input, int outputByteCount, int rate, byte domain)
    {
        ulong[] state = Absorb(input, rate, domain);
        var output = new byte[outputByteCount];
        int offset = 0;
        while (offset < outputByteCount)
        {
            Permute(state);
            int count = Math.Min(rate, outputByteCount - offset);
            ExtractBytes(state, output, offset, count);
            offset += count;
        }
        return output;
    }

    internal static ulong[] Absorb(byte[] input, int rate, byte domain)
    {
        var state = new ulong[25];
        int offset = 0;
        int remaining = input.Length;
        while (remaining >= rate)
        {
            XorBytes(state, input, offset, rate);
            Permute(state);
            offset += rate;
            remaining -= rate;
        }
        if (remaining > 0)
        {
            XorBytes(state, input, offset, remaining);
        }
        XorByte(state, domain, remaining);
        XorByte(state, 0x80, rate - 1);
        return state;
    }

    /// <summary>Squeezes <paramref name="count"/> bytes from lane offset 0 of the state.</summary>
    internal static void ExtractBytes(ulong[] state, byte[] destination, int destinationOffset, int count)
    {
        for (int i = 0; i < count; i++)
        {
            int lane = i / 8;
            int shift = (i % 8) * 8;
            destination[destinationOffset + i] = (byte)((state[lane] >> shift) & 0xff);
        }
    }

    private static void XorBytes(ulong[] state, byte[] input, int inputOffset, int count)
    {
        for (int i = 0; i < count; i++)
        {
            XorByte(state, input[inputOffset + i], i);
        }
    }

    private static void XorByte(ulong[] state, byte value, int offset)
    {
        int lane = offset / 8;
        int shift = (offset % 8) * 8;
        state[lane] ^= (ulong)value << shift;
    }

    internal static void Permute(ulong[] state)
    {
        var c = new ulong[5];
        var d = new ulong[5];
        var b = new ulong[25];

        for (int round = 0; round < 24; round++)
        {
            // Theta
            for (int x = 0; x < 5; x++)
            {
                c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
            }
            for (int x = 0; x < 5; x++)
            {
                d[x] = c[(x + 4) % 5] ^ RotateLeft(c[(x + 1) % 5], 1);
            }
            for (int x = 0; x < 5; x++)
            {
                for (int y = 0; y < 5; y++)
                {
                    state[x + 5 * y] ^= d[x];
                }
            }

            // Rho and Pi
            for (int x = 0; x < 5; x++)
            {
                for (int y = 0; y < 5; y++)
                {
                    int index = x + 5 * y;
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = RotateLeft(state[index], Rho[index]);
                }
            }

            // Chi
            for (int x = 0; x < 5; x++)
            {
                for (int y = 0; y < 5; y++)
                {
                    state[x + 5 * y] = b[x + 5 * y] ^ (~b[((x + 1) % 5) + 5 * y] & b[((x + 2) % 5) + 5 * y]);
                }
            }

            // Iota
            state[0] ^= RoundConstants[round];
        }
    }

    private static ulong RotateLeft(ulong value, int amount) =>
        amount == 0 ? value : (value << amount) | (value >> (64 - amount));

    private static readonly int[] Rho =
    {
        0, 1, 62, 28, 27,
        36, 44, 6, 55, 20,
        3, 10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2, 61, 56, 14,
    };

    private static readonly ulong[] RoundConstants =
    {
        0x0000000000000001, 0x0000000000008082,
        0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088,
        0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b,
        0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080,
        0x0000000080000001, 0x8000000080008008,
    };
}

/// <summary>Incremental SHAKE128 reader used by ML-KEM matrix expansion.</summary>
internal sealed class Shake128Xof
{
    private const int Rate = 168;

    private readonly ulong[] _state;

    internal Shake128Xof(byte[] input)
    {
        _state = Keccak.Absorb(input, Rate, 0x1f);
    }

    internal byte[] SqueezeBlocks(int blockCount)
    {
        var output = new byte[blockCount * Rate];
        int offset = 0;
        for (int i = 0; i < blockCount; i++)
        {
            Keccak.Permute(_state);
            Keccak.ExtractBytes(_state, output, offset, Rate);
            offset += Rate;
        }
        return output;
    }
}
