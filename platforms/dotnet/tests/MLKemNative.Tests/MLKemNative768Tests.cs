using Xunit;

namespace MLKemNative.Tests;

public sealed class MLKemNative768Tests
{
    [Fact]
    public void DeterministicVectorMatchesSwiftFixture()
    {
        byte[] seed = Hex(TestVector.Seed);
        byte[] coins = Hex(TestVector.Coins);
        byte[] expectedPublicKey = Hex(TestVector.PublicKey);
        byte[] expectedCiphertext = Hex(TestVector.Ciphertext);
        byte[] expectedSharedSecret = Hex(TestVector.SharedSecret);

        MLKemNative768.PrivateKey privateKey = MLKemNative768.PrivateKey.FromSeedForTesting(seed);
        MLKemNative768.Encapsulation encapsulated = privateKey.PublicKey.EncapsulateDerand(coins);

        Assert.Equal(MLKemNative768.PublicKeyBytes, expectedPublicKey.Length);
        Assert.Equal(MLKemNative768.CiphertextBytes, expectedCiphertext.Length);
        Assert.Equal(MLKemNative768.SharedSecretBytes, expectedSharedSecret.Length);
        Assert.Equal(expectedPublicKey, privateKey.PublicKey.RawRepresentation);
        Assert.Equal(expectedCiphertext, encapsulated.Ciphertext);
        Assert.Equal(expectedSharedSecret, encapsulated.SharedSecret);
        Assert.Equal(expectedSharedSecret, privateKey.Decapsulate(encapsulated.Ciphertext));
    }

    [Fact]
    public void ReferenceAllZeroAllOneVectorMatchesSwiftFixture()
    {
        byte[] seed = new byte[MLKemNative768.KeypairSeedBytes];
        byte[] coins = new byte[MLKemNative768.EncapsulationSeedBytes];
        coins[0] = 1;
        byte[] expectedSharedSecret = Hex(TestVector.ZeroOneSharedSecret);

        MLKemNative768.PrivateKey privateKey = MLKemNative768.PrivateKey.FromSeedForTesting(seed);
        MLKemNative768.Encapsulation encapsulated = privateKey.PublicKey.EncapsulateDerand(coins);

        Assert.Equal(expectedSharedSecret, encapsulated.SharedSecret);
        Assert.Equal(expectedSharedSecret, privateKey.Decapsulate(encapsulated.Ciphertext));
    }

    [Fact]
    public void RoundTripGenerateRepresentationAndEncapsulation()
    {
        MLKemNative768.PrivateKey privateKey = MLKemNative768.PrivateKey.Generate();
        MLKemNative768.PrivateKey loaded = MLKemNative768.PrivateKey.FromRepresentation(privateKey.Representation);

        Assert.Equal(MLKemNative768.PrivateKeyRepresentationBytes, privateKey.Representation.Length);
        Assert.Equal(privateKey.Representation, loaded.Representation);
        Assert.Equal(privateKey.PublicKey.RawRepresentation, loaded.PublicKey.RawRepresentation);

        MLKemNative768.Encapsulation encapsulated = loaded.PublicKey.Encapsulate();
        byte[] opened = loaded.Decapsulate(encapsulated.Ciphertext);

        Assert.Equal(MLKemNative768.CiphertextBytes, encapsulated.Ciphertext.Length);
        Assert.Equal(encapsulated.SharedSecret, opened);
    }

    [Fact]
    public void TamperedCiphertextUsesFallbackSecret()
    {
        MLKemNative768.PrivateKey privateKey = MLKemNative768.PrivateKey.FromSeedForTesting(Hex(TestVector.Seed));
        MLKemNative768.Encapsulation encapsulated = privateKey.PublicKey.EncapsulateDerand(Hex(TestVector.Coins));
        byte[] tampered = encapsulated.Ciphertext;
        tampered[0] ^= 0x01;

        byte[] opened = privateKey.Decapsulate(tampered);

        Assert.NotEqual(encapsulated.SharedSecret, opened);
    }

    [Fact]
    public void IncrementalPart1Part2EquivalentToOneShotEncapsulation()
    {
        byte[] coins = Hex(TestVector.Coins);
        MLKemNative768.PrivateKey privateKey = MLKemNative768.PrivateKey.FromSeedForTesting(Hex(TestVector.Seed));
        MLKemNative768.Encapsulation full = privateKey.PublicKey.EncapsulateDerand(coins);

        MLKemNative768.IncrementalPublicKey incrementalKey =
            MLKemNative768.PublicKeyToIncremental(privateKey.PublicKey);
        byte[] reconstructed = MLKemNative768.PublicKeyFromIncremental(
            incrementalKey.Header,
            incrementalKey.EncapsulationKeyVector);
        MLKemNative768.IncrementalPublicKey reconstructedKey = new(
            incrementalKey.Header,
            incrementalKey.EncapsulationKeyVector);
        MLKemNative768.IncrementalEncapsulationPart1 part1 =
            MLKemNative768.EncapsulatePart1(incrementalKey.Header, coins);
        byte[] part2 = MLKemNative768.EncapsulatePart2(
            part1.EncapsulationSecret,
            incrementalKey.Header,
            incrementalKey.EncapsulationKeyVector);

        Assert.Equal(MLKemNative768.IncrementalHeaderBytes, incrementalKey.Header.Length);
        Assert.Equal(MLKemNative768.EncapsulationKeyVectorBytes, incrementalKey.EncapsulationKeyVector.Length);
        Assert.Equal(privateKey.PublicKey.RawRepresentation, reconstructed);
        Assert.Equal(privateKey.PublicKey.RawRepresentation, reconstructedKey.PublicKey.RawRepresentation);
        Assert.Equal(MLKemNative768.CiphertextPart1Bytes, part1.CiphertextPart1.Length);
        Assert.Equal(MLKemNative768.CiphertextPart2Bytes, part2.Length);
        Assert.Equal(full.Ciphertext, Concat(part1.CiphertextPart1, part2));
        Assert.Equal(full.SharedSecret, part1.SharedSecret);
        Assert.Equal(full.SharedSecret, privateKey.DecapsulateParts(part1.CiphertextPart1, part2));
    }

    [Fact]
    public void InvalidInputsAreRejected()
    {
        MLKemNative768.PrivateKey privateKey = MLKemNative768.PrivateKey.FromSeedForTesting(Hex(TestVector.Seed));

        Assert.Throws<MLKemException.InvalidPublicKey>(
            () => new MLKemNative768.PublicKey(Repeat(0xff, MLKemNative768.PublicKeyBytes)));
        Assert.Throws<MLKemException.InvalidPrivateKeyRepresentation>(
            () => MLKemNative768.PrivateKey.FromRepresentation(new byte[64]));
        Assert.Throws<MLKemException.InvalidCiphertext>(
            () => privateKey.Decapsulate(new byte[MLKemNative768.CiphertextBytes - 1]));

        byte[] representation = privateKey.Representation;
        representation[^1] ^= 0x01;
        Assert.Throws<MLKemException.InvalidPrivateKeyRepresentation>(
            () => MLKemNative768.PrivateKey.FromRepresentation(representation));
    }

    [Fact]
    public void InvalidIncrementalInputsAreRejected()
    {
        MLKemNative768.PrivateKey privateKey = MLKemNative768.PrivateKey.FromSeedForTesting(Hex(TestVector.Seed));
        MLKemNative768.IncrementalPublicKey incrementalKey =
            MLKemNative768.PublicKeyToIncremental(privateKey.PublicKey);

        Assert.Throws<MLKemException.InvalidIncrementalHeader>(
            () => MLKemNative768.PublicKeyFromIncremental(
                new byte[MLKemNative768.IncrementalHeaderBytes - 1],
                incrementalKey.EncapsulationKeyVector));
        Assert.Throws<MLKemException.InvalidEncapsulationKeyVector>(
            () => MLKemNative768.PublicKeyFromIncremental(
                incrementalKey.Header,
                new byte[MLKemNative768.EncapsulationKeyVectorBytes - 1]));

        byte[] tamperedHeader = incrementalKey.Header;
        tamperedHeader[^1] ^= 0x01;
        Assert.Throws<MLKemException.InvalidIncrementalHeader>(
            () => MLKemNative768.PublicKeyFromIncremental(tamperedHeader, incrementalKey.EncapsulationKeyVector));
        Assert.Throws<MLKemException.InvalidIncrementalHeader>(
            () => MLKemNative768.EncapsulatePart1(new byte[MLKemNative768.IncrementalHeaderBytes - 1]));
        Assert.Throws<MLKemException.InvalidIncrementalEncapsulationSecret>(
            () => MLKemNative768.EncapsulatePart2(
                new byte[MLKemNative768.IncrementalEncapsulationSecretBytes - 1],
                incrementalKey.Header,
                incrementalKey.EncapsulationKeyVector));
        Assert.Throws<MLKemException.InvalidCiphertext>(
            () => privateKey.DecapsulateParts(
                new byte[MLKemNative768.CiphertextPart1Bytes - 1],
                new byte[MLKemNative768.CiphertextPart2Bytes]));
        Assert.Throws<MLKemException.InvalidCiphertext>(
            () => privateKey.DecapsulateParts(
                new byte[MLKemNative768.CiphertextPart1Bytes],
                new byte[MLKemNative768.CiphertextPart2Bytes - 1]));
    }

    [Fact]
    public void ReturnedArraysAreDefensiveCopies()
    {
        MLKemNative768.PrivateKey privateKey = MLKemNative768.PrivateKey.FromSeedForTesting(Hex(TestVector.Seed));
        MLKemNative768.Encapsulation encapsulation = privateKey.PublicKey.EncapsulateDerand(Hex(TestVector.Coins));
        MLKemNative768.IncrementalPublicKey incrementalKey =
            MLKemNative768.PublicKeyToIncremental(privateKey.PublicKey);
        MLKemNative768.IncrementalEncapsulationPart1 part1 =
            MLKemNative768.EncapsulatePart1(incrementalKey.Header, Hex(TestVector.Coins));

        MutateFirstByte(privateKey.Representation);
        MutateFirstByte(privateKey.PublicKey.RawRepresentation);
        MutateFirstByte(encapsulation.Ciphertext);
        MutateFirstByte(encapsulation.SharedSecret);
        MutateFirstByte(incrementalKey.Header);
        MutateFirstByte(incrementalKey.EncapsulationKeyVector);
        MutateFirstByte(part1.EncapsulationSecret);
        MutateFirstByte(part1.CiphertextPart1);
        MutateFirstByte(part1.SharedSecret);

        Assert.Equal(MLKemNative768.PrivateKeyRepresentationBytes, privateKey.Representation.Length);
        Assert.Equal(Hex(TestVector.PublicKey), privateKey.PublicKey.RawRepresentation);
        Assert.Equal(Hex(TestVector.Ciphertext), encapsulation.Ciphertext);
        Assert.Equal(Hex(TestVector.SharedSecret), encapsulation.SharedSecret);
        Assert.Equal(MLKemNative768.IncrementalHeaderBytes, incrementalKey.Header.Length);
        Assert.Equal(MLKemNative768.EncapsulationKeyVectorBytes, incrementalKey.EncapsulationKeyVector.Length);
        Assert.Equal(MLKemNative768.IncrementalEncapsulationSecretBytes, part1.EncapsulationSecret.Length);
        Assert.Equal(MLKemNative768.CiphertextPart1Bytes, part1.CiphertextPart1.Length);
        Assert.Equal(Hex(TestVector.SharedSecret), part1.SharedSecret);
    }

    [Fact]
    public void KeccakKnownAnswerTestsPass()
    {
        Assert.Equal(
            Hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
            Keccak.Sha3256(Array.Empty<byte>()));
        Assert.Equal(
            Hex("""
            a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b
            2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26
            """),
            Keccak.Sha3512(Array.Empty<byte>()));
        Assert.Equal(
            Hex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"),
            Keccak.Shake128(Array.Empty<byte>(), 32));
        Assert.Equal(
            Hex("""
            46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f
            d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be
            """),
            Keccak.Shake256(Array.Empty<byte>(), 64));
    }

    private static byte[] Hex(string hex)
    {
        string clean = new(hex.Where(c => !char.IsWhiteSpace(c)).ToArray());
        if (clean.Length % 2 != 0)
        {
            throw new InvalidOperationException("Invalid test hex.");
        }

        var bytes = new byte[clean.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(clean.Substring(2 * i, 2), 16);
        }

        return bytes;
    }

    private static byte[] Repeat(byte value, int count)
    {
        var bytes = new byte[count];
        Array.Fill(bytes, value);
        return bytes;
    }

    private static byte[] Concat(byte[] first, byte[] second)
    {
        var result = new byte[first.Length + second.Length];
        Array.Copy(first, 0, result, 0, first.Length);
        Array.Copy(second, 0, result, first.Length, second.Length);
        return result;
    }

    private static void MutateFirstByte(byte[] bytes)
    {
        bytes[0] ^= 0x01;
    }
}

internal static class TestVector
{
    internal const string Seed = """
    000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
    202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
    """;

    internal const string Coins = """
    404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
    """;

    internal const string PublicKey = """
    298aa10d423c8dda069d02bc59e6cdf03a096b8b3da4cab9b80ca4a14907672c
    cef1ec4faf234a0bc5b7e9d473f2b3133b3b26a1d175cb67a7805919699c02f7
    6531b99c5f89180704bb4ca4535c5b8972679c660a07c5e514b87009c862eb8f
    5157695efb3fc40a9def6b81c1cc02a249ae4f094ad0d9bd3485c1c1c6808052
    0a7c8c632032cee738154e5c5176c07da56024776a430fe76eacf665a3f7b832
    102215bc82f10939c8355704336a8fac1d81e4bb0485aa5d7c74d6b59bbe5c5e
    972a0d8bac411b55b5d5557cd680a1a8f71b4eb86bc48c9a0509731a54bd9d72
    90b27963e4372dc9b199cfdcac0b01acd28a62395112e4c43648d622c48c8234
    d01440e8cc376c927f23a5afc9ac0474c662274e424525c8552ece3b3fe26516
    de901bc7d515bde89558e626c95c80b93342f8010004f39e6c6c94871c5e344c
    ab3966c835f9a96a59afd31c40286b38b1c1a78470bab947518934453ce86736
    a919f1f5a6d510a86f5454fc3980cb5c765bd2bd5f7b36b1410d6635c8ceb47c
    4dda0d76a28eac939c71c3024804866c71626658442163c2c22117e50acefce6
    378a985652302a4ef0c2ce0cc716b7796e2b6b2e3777dfa1ac3da259a31b5a9b
    530f8cb638a81a62ac301849abaf95a7301bda30068909bfdb7e67dbccbb38a5
    551a25b1a3a0f685748ad5753d8880f0016c627486166384c5571fe236590036
    4d038311e2d875db366686932b5ec602430a369e87a6ef5c338786657825bd4c
    057aceb923eb0935e6905e63b4ced7f80857a773dd64b150d26612ea9ac12052
    db2017bf1843ccb4b3281b690dc728adfa85c00281b8e3c09287335f856b4fc2
    892f69a2f57921ada01914c40988662d57769662a786351b9b66493dab79594d
    986de2100d65ba0ff4ea58b81538d24a4435a258fac25404aa7f41f658b13850
    65e158dcb60115732720f40459aaac15e406953a90ac52997d1ccd070060efc6
    5db9e653354467fad56ec713c86e7540c423acf2669f52fa6f4ac6888d871ef3
    e847c029a8aafbb92e17b24aa079b1f419ba6175b442afb11909d4a56b70a033
    5b28739218aa7c9348e2c3c2f3eb3d15a41e6417c0dd94bfeb21419b311a7bb1
    3a180bbe833218a9a6b17447cc85f225859587a73077049acbcfd44d0f025438
    e15d1538270d586e1bf83192a9459cf63c0e972f85297679831ecf121509851c
    b8340f6f107b0fa1a0efd1b36a8189bc085c4f5cb784e553f41b918f80397ce1
    956f785bee377ca9aa8be6998ada30c26b7c3d8c6b55254cc96203b20c42aee0
    ac4e1ebb408e49a9e3f879d0ab0785eb7025425d1305a2299c015e120d163b0e
    19494ce57253d0246d182745cb8197ab7438b3c1bb7972bec5a306eba3567855
    c014699fef65ae54c770a0d85c18400cf642aedc660777ba4b138502bd5a7812
    f621f84a48296b98dd4322b6f15828b8a8f0e00a8ba44a53c3a8b143571b0740
    abd567daf1cde9c79c204b6d5e259d1766a31bbbcb4e6a05cf4502176b301c1c
    2f41247750157bcec85e809b30a4d60d7747cdd0f5b99aa8c826987517793aaa
    8080a0b124a8558df72bbe37b75f4edbb6be8216d6c633fb2b2280e25113d869
    5e43481c3eeb397eb192505229b67a201ea893c3e2cb32da8bc342fa4dea0578
    """;

    internal const string Ciphertext = """
    695a60d9c79f08343ed9ff5802582063c2ca3a648e543d924affbb39ef4de656
    591f0d7689e6626be7ea7fedaf134e2c27c6797c73a5edaf16808f141c8afcf3
    1614e8ab665379573e4d0a2037cbf776048167ba53576001a2596402cf24b5d4
    5362bc893ceaef3599f76b10812e626002e66db5c5b0f2b9a7080e32db68dcc8
    d04c24f8461a58bb7e47efe670d740ad8af9820033845ef5f880f26f0e00adb2
    abef876f5270477ebbb02de6787ce72ca8785fb181f46c3ff7ae3787c25c68cc
    ceefb3551875b9d77c4d439b6050eb382aacf9e744227e8c46e0a9a55838ea70
    34f5b4bcb61f1023a80186e795f4b3d8ae93988994224fa2d83e21711670da01
    e2b3e272f81616c0bc88cc46f641d16e0d0c0924cf4a4a5c1a9128c226d4918a
    a39bef94199dfffa33876ef0bfa0d9560d25f5ba08068d5271f32d2f9d88bcf5
    3c7dcf811a8d5efe617f5e05700d3478d3cb7932528d1bceb240198a4cf8752c
    aea3d387f00759a1356b7a5bf1838d26c3573e92e69f0f57c06e8c25459eb83e
    12cdd75f541a81ce710eafce2984783f30e37b327ff93b72297c6cd8c78c185a
    d53864952069d7d6c3bc633ae5e1a5925855df0b7e714bbde245f68822e0950c
    23c96d6111753a6ed0c46cce437f53b6bb708c1a3e25979733198d9879e3237e
    769471f922e579f37cfd641d29bdcfdbaa81edae09aeb046366e0376d04282d1
    7778a8d54774e8c9be3c822b1e90cd8895abc1db8951b7687f63fee50ec43faf
    23730b15189e7c982b22d896a972da3c2ee529bb5fe63630c9c2ddfb9d1e4263
    a3d49af2832053d97efa2bd1782f25d7b864d6fb3708bfb9d4bc6c2cc6458d4f
    1459995db387e8b503825a4496c735252aa630a1bcaa7a2674727396dcaf6703
    0b53473951651dc26c22476bfd11d33206af0ff035ed035e34716c905e8ddf04
    3a4cdae145238d8f612dbcb75e879653bb9e2657dab58b944ff34f977fe15ce9
    07f6814a5f92338774e6f2ab5257d24917decdd158c6d4594189f42a9b7fa915
    9a8af6aa825ba904654e08c894901298ffb27239ddea8283dd45b876036c0aec
    f03583ba444529757444c857fff6e4f8ed48f8a180adea54979a678f16dc6ac8
    edcc8e72ed08e96082f0ff4520dc635d4a846a3026fd86a48b1297e0cdfc0600
    8793e783bde1c3fc6a71871e66b1feb560495817aabbdc59f0149f3e76add9b5
    bd6ce34734de7593ed607efb84c6e732960c744c908a9cb8947375a55b55fa2f
    0cd6742b75c10f65522d3844bed9b05bd441bbbea17cfbabdaef9847a0edd9c8
    329a762e34e5396014d88b4d344f250aaddefd917bb2120d1169c79cb09f59ba
    d21850752c1099fff98b71bcdaab76f7063323e78faa521cd243f74ddc7f7775
    aa79960622e13580a6831e69bb7f2321d141d35da88317719078d4db319f3085
    94c26836503f62362c40005022937c1298a928c040879661349a7b5362d0a75f
    2893b97a2600d5337239a70a6b64a457e6dfd5c74d462e7e790bb9ef3cee1461
    """;

    internal const string SharedSecret = """
    9cddd089ffe70e3996e76f7c8d06746df34d07e8657bc0fcf2bb0e1c3084aea1
    """;

    internal const string ZeroOneSharedSecret = """
    8521abc814c767704fa625d93595d00379a8b370352ca4bab3a68246630db08b
    """;
}
