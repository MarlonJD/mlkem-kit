package io.github.marlonjd.mlkemnative

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MLKEMNative768InstrumentedTest {
    @Test
    fun generateLoadRepresentationRoundTrip() {
        val privateKey = MLKEMNative768.PrivateKey.generate()

        assertEquals(
            MLKEMNative768.PRIVATE_KEY_REPRESENTATION_BYTES,
            privateKey.representation.size,
        )

        val loaded = MLKEMNative768.PrivateKey.fromRepresentation(privateKey.representation)
        assertArrayEquals(
            privateKey.publicKey.rawRepresentation,
            loaded.publicKey.rawRepresentation,
        )

        val encapsulation = privateKey.publicKey.encapsulate()
        assertArrayEquals(
            encapsulation.sharedSecret,
            loaded.decapsulate(encapsulation.ciphertext),
        )
    }

    @Test
    fun encapsulateDecapsulateRoundTrip() {
        val privateKey = MLKEMNative768.PrivateKey.generate()
        val encapsulation = privateKey.publicKey.encapsulate()

        assertEquals(MLKEMNative768.CIPHERTEXT_BYTES, encapsulation.ciphertext.size)
        assertEquals(MLKEMNative768.SHARED_SECRET_BYTES, encapsulation.sharedSecret.size)
        assertArrayEquals(
            encapsulation.sharedSecret,
            privateKey.decapsulate(encapsulation.ciphertext),
        )
    }

    @Test
    fun deterministicVectorMatchesSwiftFixture() {
        val privateKey = MLKEMNative768.PrivateKey.fromSeedForTesting(VECTOR_SEED)
        assertArrayEquals(VECTOR_PUBLIC_KEY, privateKey.publicKey.rawRepresentation)

        val encapsulation = MLKEMNative768.encapsulateDerandForTesting(
            privateKey.publicKey.rawRepresentation,
            VECTOR_COINS,
        )
        assertArrayEquals(VECTOR_CIPHERTEXT, encapsulation.ciphertext)
        assertArrayEquals(VECTOR_SHARED_SECRET, encapsulation.sharedSecret)
        assertArrayEquals(VECTOR_SHARED_SECRET, privateKey.decapsulate(VECTOR_CIPHERTEXT))
    }

    @Test
    fun incrementalPublicKeySplitAndReconstructRoundTrip() {
        val incremental = MLKEMNative768.publicKeyToIncremental(VECTOR_PUBLIC_KEY)

        assertEquals(MLKEMNative768.incrementalHeaderBytes, incremental.header.size)
        assertEquals(
            MLKEMNative768.encapsulationKeyVectorBytes,
            incremental.encapsulationKeyVector.size,
        )
        assertArrayEquals(
            VECTOR_PUBLIC_KEY,
            MLKEMNative768.publicKeyFromIncremental(
                incremental.header,
                incremental.encapsulationKeyVector,
            ),
        )
    }

    @Test
    fun incrementalEncapsulationMatchesNormalDeterministicEncapsulation() {
        val incremental = MLKEMNative768.publicKeyToIncremental(VECTOR_PUBLIC_KEY)
        val part1 = MLKEMNative768.encapsulatePart1DerandForTesting(
            incremental.header,
            VECTOR_COINS,
        )
        val part2 = MLKEMNative768.encapsulatePart2(
            part1.encapsSecret,
            incremental.header,
            incremental.encapsulationKeyVector,
        )

        assertEquals(
            MLKEMNative768.incrementalEncapsulationSecretBytes,
            part1.encapsSecret.size,
        )
        assertArrayEquals(
            VECTOR_CIPHERTEXT.copyOfRange(0, MLKEMNative768.ciphertextPart1Bytes),
            part1.ciphertextPart1,
        )
        assertArrayEquals(
            VECTOR_CIPHERTEXT.copyOfRange(
                MLKEMNative768.ciphertextPart1Bytes,
                MLKEMNative768.ciphertextBytes,
            ),
            part2,
        )
        assertArrayEquals(VECTOR_SHARED_SECRET, part1.sharedSecret)
    }

    @Test
    fun incrementalDecapsulatePartsMatchesNormalDecapsulation() {
        val privateKey = MLKEMNative768.PrivateKey.fromSeedForTesting(VECTOR_SEED)
        val incremental = MLKEMNative768.publicKeyToIncremental(privateKey.publicKey)
        val part1 = MLKEMNative768.encapsulatePart1DerandForTesting(
            incremental.header,
            VECTOR_COINS,
        )
        val part2 = MLKEMNative768.encapsulatePart2(
            part1.encapsulationSecret,
            incremental.header,
            incremental.encapsulationKeyVector,
        )

        assertArrayEquals(
            VECTOR_SHARED_SECRET,
            MLKEMNative768.decapsulateParts(privateKey, part1.ciphertextPart1, part2),
        )
        assertArrayEquals(
            privateKey.decapsulate(VECTOR_CIPHERTEXT),
            privateKey.decapsulateParts(part1.ciphertextPart1, part2),
        )
    }

    @Test
    fun invalidIncrementalSizesAreRejected() {
        val privateKey = MLKEMNative768.PrivateKey.fromSeedForTesting(VECTOR_SEED)
        val incremental = MLKEMNative768.publicKeyToIncremental(privateKey.publicKey)
        val part1 = MLKEMNative768.encapsulatePart1DerandForTesting(
            incremental.header,
            VECTOR_COINS,
        )

        assertThrows<MLKEMException.InvalidIncrementalHeader> {
            MLKEMNative768.publicKeyFromIncremental(
                ByteArray(MLKEMNative768.incrementalHeaderBytes - 1),
                incremental.encapsulationKeyVector,
            )
        }
        assertThrows<MLKEMException.InvalidEncapsulationKeyVector> {
            MLKEMNative768.publicKeyFromIncremental(
                incremental.header,
                ByteArray(MLKEMNative768.encapsulationKeyVectorBytes - 1),
            )
        }
        assertThrows<MLKEMException.InvalidIncrementalHeader> {
            MLKEMNative768.encapsulatePart1(
                ByteArray(MLKEMNative768.incrementalHeaderBytes - 1),
            )
        }
        assertThrows<MLKEMException.InvalidIncrementalEncapsulationSecret> {
            MLKEMNative768.encapsulatePart2(
                ByteArray(MLKEMNative768.incrementalEncapsulationSecretBytes - 1),
                incremental.header,
                incremental.encapsulationKeyVector,
            )
        }
        assertThrows<MLKEMException.InvalidCiphertext> {
            MLKEMNative768.decapsulateParts(
                privateKey,
                ByteArray(MLKEMNative768.ciphertextPart1Bytes - 1),
                ByteArray(MLKEMNative768.ciphertextPart2Bytes),
            )
        }
        assertThrows<MLKEMException.InvalidCiphertext> {
            MLKEMNative768.decapsulateParts(
                privateKey,
                part1.ciphertextPart1,
                ByteArray(MLKEMNative768.ciphertextPart2Bytes - 1),
            )
        }
    }

    @Test
    fun tamperedIncrementalHeaderHashIsRejected() {
        val incremental = MLKEMNative768.publicKeyToIncremental(VECTOR_PUBLIC_KEY)
        val tamperedHeader = incremental.header
        tamperedHeader[tamperedHeader.lastIndex] =
            (tamperedHeader[tamperedHeader.lastIndex].toInt() xor 0x01).toByte()

        assertThrows<MLKEMException.InvalidIncrementalHeader> {
            MLKEMNative768.publicKeyFromIncremental(
                tamperedHeader,
                incremental.encapsulationKeyVector,
            )
        }
        assertThrows<MLKEMException.InvalidIncrementalHeader> {
            MLKEMNative768.encapsulatePart2(
                ByteArray(MLKEMNative768.incrementalEncapsulationSecretBytes),
                tamperedHeader,
                incremental.encapsulationKeyVector,
            )
        }
    }

    @Test
    fun byteInvariantsMatchMlKem768() {
        val privateKey = MLKEMNative768.PrivateKey.fromSeedForTesting(VECTOR_SEED)
        val encapsulation = MLKEMNative768.encapsulateDerandForTesting(
            privateKey.publicKey.rawRepresentation,
            VECTOR_COINS,
        )

        assertEquals(1184, privateKey.publicKey.rawRepresentation.size)
        assertEquals(1088, encapsulation.ciphertext.size)
        assertEquals(32, encapsulation.sharedSecret.size)
        assertEquals(1253, privateKey.representation.size)
        assertEquals(64, MLKEMNative768.incrementalHeaderBytes)
        assertEquals(1152, MLKEMNative768.encapsulationKeyVectorBytes)
        assertEquals(960, MLKEMNative768.ciphertextPart1Bytes)
        assertEquals(128, MLKEMNative768.ciphertextPart2Bytes)
        assertEquals(64, MLKEMNative768.incrementalEncapsulationSecretBytes)
    }

    @Test
    fun invalidPublicKeyLengthAndContentAreRejected() {
        assertThrows<MLKEMException.InvalidPublicKey> {
            MLKEMNative768.PublicKey(ByteArray(MLKEMNative768.PUBLIC_KEY_BYTES - 1))
        }

        assertThrows<MLKEMException.InvalidPublicKey> {
            MLKEMNative768.PublicKey(ByteArray(MLKEMNative768.PUBLIC_KEY_BYTES) { 0xff.toByte() })
        }
    }

    @Test
    fun invalidPrivateRepresentationIsRejected() {
        val privateKey = MLKEMNative768.PrivateKey.fromSeedForTesting(VECTOR_SEED)

        assertThrows<MLKEMException.InvalidPrivateKeyRepresentation> {
            MLKEMNative768.PrivateKey.fromRepresentation(
                ByteArray(MLKEMNative768.PRIVATE_KEY_REPRESENTATION_BYTES - 1),
            )
        }

        val badMagic = privateKey.representation
        badMagic[0] = 'X'.code.toByte()
        assertThrows<MLKEMException.InvalidPrivateKeyRepresentation> {
            MLKEMNative768.PrivateKey.fromRepresentation(badMagic)
        }

        val publicKeyMismatch = privateKey.representation
        publicKeyMismatch[publicKeyMismatch.lastIndex] =
            (publicKeyMismatch[publicKeyMismatch.lastIndex].toInt() xor 0x01).toByte()
        assertThrows<MLKEMException.InvalidPrivateKeyRepresentation> {
            MLKEMNative768.PrivateKey.fromRepresentation(publicKeyMismatch)
        }
    }

    @Test
    fun invalidCiphertextLengthIsRejected() {
        val privateKey = MLKEMNative768.PrivateKey.fromSeedForTesting(VECTOR_SEED)

        assertThrows<MLKEMException.InvalidCiphertext> {
            privateKey.decapsulate(ByteArray(MLKEMNative768.CIPHERTEXT_BYTES - 1))
        }
    }

    @Test
    fun returnedByteArraysAreDefensiveCopies() {
        val privateKey = MLKEMNative768.PrivateKey.fromSeedForTesting(VECTOR_SEED)
        val originalRepresentation = privateKey.representation
        val mutatedRepresentation = privateKey.representation
        mutatedRepresentation[0] = 'X'.code.toByte()
        assertArrayEquals(originalRepresentation, privateKey.representation)

        val publicKeyBytes = privateKey.publicKey.rawRepresentation
        val publicKey = MLKEMNative768.PublicKey(publicKeyBytes)
        publicKeyBytes.fill(0xff.toByte())
        assertArrayEquals(VECTOR_PUBLIC_KEY, publicKey.rawRepresentation)

        val returnedPublicKey = publicKey.rawRepresentation
        returnedPublicKey[0] = (returnedPublicKey[0].toInt() xor 0x01).toByte()
        assertArrayEquals(VECTOR_PUBLIC_KEY, publicKey.rawRepresentation)

        val encapsulation = MLKEMNative768.encapsulateDerandForTesting(
            publicKey.rawRepresentation,
            VECTOR_COINS,
        )
        val originalCiphertext = encapsulation.ciphertext
        val returnedCiphertext = encapsulation.ciphertext
        returnedCiphertext[0] = (returnedCiphertext[0].toInt() xor 0x01).toByte()
        assertArrayEquals(originalCiphertext, encapsulation.ciphertext)

        val originalSharedSecret = encapsulation.sharedSecret
        val returnedSharedSecret = encapsulation.sharedSecret
        returnedSharedSecret[0] = (returnedSharedSecret[0].toInt() xor 0x01).toByte()
        assertArrayEquals(originalSharedSecret, encapsulation.sharedSecret)
        assertFalse(returnedSharedSecret.contentEquals(encapsulation.sharedSecret))
    }

    private inline fun <reified T : Throwable> assertThrows(block: () -> Unit) {
        try {
            block()
            fail("Expected ${T::class.java.name}")
        } catch (exception: Throwable) {
            assertTrue(
                "Expected ${T::class.java.name}, got ${exception::class.java.name}",
                exception is T,
            )
        }
    }

    private companion object {
        val VECTOR_SEED =
            hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
        val VECTOR_COINS =
            hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf")
        val VECTOR_PUBLIC_KEY =
            hex("298aa10d423c8dda069d02bc59e6cdf03a096b8b3da4cab9b80ca4a14907672ccef1ec4faf234a0bc5b7e9d473f2b3133b3b26a1d175cb67a7805919699c02f76531b99c5f89180704bb4ca4535c5b8972679c660a07c5e514b87009c862eb8f5157695efb3fc40a9def6b81c1cc02a249ae4f094ad0d9bd3485c1c1c68080520a7c8c632032cee738154e5c5176c07da56024776a430fe76eacf665a3f7b832102215bc82f10939c8355704336a8fac1d81e4bb0485aa5d7c74d6b59bbe5c5e972a0d8bac411b55b5d5557cd680a1a8f71b4eb86bc48c9a0509731a54bd9d7290b27963e4372dc9b199cfdcac0b01acd28a62395112e4c43648d622c48c8234d01440e8cc376c927f23a5afc9ac0474c662274e424525c8552ece3b3fe26516de901bc7d515bde89558e626c95c80b93342f8010004f39e6c6c94871c5e344cab3966c835f9a96a59afd31c40286b38b1c1a78470bab947518934453ce86736a919f1f5a6d510a86f5454fc3980cb5c765bd2bd5f7b36b1410d6635c8ceb47c4dda0d76a28eac939c71c3024804866c71626658442163c2c22117e50acefce6378a985652302a4ef0c2ce0cc716b7796e2b6b2e3777dfa1ac3da259a31b5a9b530f8cb638a81a62ac301849abaf95a7301bda30068909bfdb7e67dbccbb38a5551a25b1a3a0f685748ad5753d8880f0016c627486166384c5571fe2365900364d038311e2d875db366686932b5ec602430a369e87a6ef5c338786657825bd4c057aceb923eb0935e6905e63b4ced7f80857a773dd64b150d26612ea9ac12052db2017bf1843ccb4b3281b690dc728adfa85c00281b8e3c09287335f856b4fc2892f69a2f57921ada01914c40988662d57769662a786351b9b66493dab79594d986de2100d65ba0ff4ea58b81538d24a4435a258fac25404aa7f41f658b1385065e158dcb60115732720f40459aaac15e406953a90ac52997d1ccd070060efc65db9e653354467fad56ec713c86e7540c423acf2669f52fa6f4ac6888d871ef3e847c029a8aafbb92e17b24aa079b1f419ba6175b442afb11909d4a56b70a0335b28739218aa7c9348e2c3c2f3eb3d15a41e6417c0dd94bfeb21419b311a7bb13a180bbe833218a9a6b17447cc85f225859587a73077049acbcfd44d0f025438e15d1538270d586e1bf83192a9459cf63c0e972f85297679831ecf121509851cb8340f6f107b0fa1a0efd1b36a8189bc085c4f5cb784e553f41b918f80397ce1956f785bee377ca9aa8be6998ada30c26b7c3d8c6b55254cc96203b20c42aee0ac4e1ebb408e49a9e3f879d0ab0785eb7025425d1305a2299c015e120d163b0e19494ce57253d0246d182745cb8197ab7438b3c1bb7972bec5a306eba3567855c014699fef65ae54c770a0d85c18400cf642aedc660777ba4b138502bd5a7812f621f84a48296b98dd4322b6f15828b8a8f0e00a8ba44a53c3a8b143571b0740abd567daf1cde9c79c204b6d5e259d1766a31bbbcb4e6a05cf4502176b301c1c2f41247750157bcec85e809b30a4d60d7747cdd0f5b99aa8c826987517793aaa8080a0b124a8558df72bbe37b75f4edbb6be8216d6c633fb2b2280e25113d8695e43481c3eeb397eb192505229b67a201ea893c3e2cb32da8bc342fa4dea0578")
        val VECTOR_CIPHERTEXT =
            hex("de8df69f8b171cf4f73b67350bd6aa88161a924c52e502119f637c1e2d6186addfcb326f135e60995450a4583ba4ed8fd88d936bca4794610d9e1a4777fa8686f7a8185e99394ad3d804f9200b09c899405b6ed2c913ead319b8a0125bbc28c7f6a2332fba6287197a2a594d76f95e0575b6f2800c0ae71e55954318994896f3e65f03bfda5e05616d2785c0bc51dca5a5107ee2e6bd534fc9cd61825bbab03aa7364270fe2f2d76502977d86505d038d69c04a31e0427fce1f35c0d3ea7029e64043d4d9c285d0c17a7de9b7811c9fcb7ae5c60096c837a530d156e653fe85cd52b976406e0a47876b7bc1d168b5cc6a78b8125d2a3f1870ae29f6e1c7aa1e3b87fc4147b5feb5c09bb52098db3cf62c5a2131dbab63a5593df6d7fc06f628eedc6fba9d47abaad74f0a44d18fd2f677566eee2792fa4e864cbef906985a72ffbdc0fb52cd57d37c5fb7ae822472264ad9022d1c4ab60e45f6781d126211069bb4211314f4a0f96ca5fd4b5f410730c81abd1e94ddd5f0ae35b7a186dcb9d7ef54d7919b1e020067fc090d26b84f771c702787684e2840c3b987f44084477466368528f81cb4fae33d859b7eacf4cb535bac262ff6997a43ca9f65ce8d113ebbbd07fb351622341249591fed826e3e2b24759d73c4a5519a668710e3884f333a0f61819e5e3421f1b16933155cc8c97126c00587884a4127eaf96cfeca419d7ac349adfb2ecbea3acb9891173053353dca653ef5d1c6c4fbaaf59465994320955fe6b86595fb403d002b411f8d0ec716f1a8e304b2b0dd3957aaafdc677b68af63b62a81aa87e68c19d50ecfff54fd645e664a28575187b010622b5dd2df19683ab7b46c90db15eaf6be38135bc17c08f6cc4a4dfddd1cc8b06b01099e44995caea4f2581655a550801665067fd46fa0f54055b5818a19cc9137cb3cc46297a30e0df511180430ae934c23caa1bd71b0e7339a17b88884ec3e03d4eded1c63246d0c754961ff2eaa5deecbeff8cf871fb496e355ad0b240a7b97e3e04996f0fb7dc4b45bf1789190530b4845b212ab20117cd2c5c141990d4212c07778c09b3c336ed05adb2f32f48cfdfb6a3181a917c2d278f4da58ba9465d4ae24e91faf37ca85409a502f997e0f14833967c78b6eb9412a4f9ae8a04b9453aad899f4e783ee5f06e7b22cf40e998ddabf49739678393e3d1138b9c30ff3d61bcb118ff16fc291219f3b011750e3dad8fe651b90d02b857bb46382e86b3d3239fbb1a9214b975807d688867e9011dc016640f63184cc39a5ac18728c429323121b57d18132f5cafd25bb4976ddaec033357d35a88d613f4653b2621db5aabfe70121dac232d980dc38acb93e7abb5d4fae0cd054a6229efa11700bd9f5750874cdec31e35bcc665dc0ef15eb893435a512165feb08b6b45d187406165532d3ca2dac022015c994eee652fe348469e0e3929e79ffca8c280de63e51a1e7f380f4bfa513608a1e2ec0084570bc8df620d8c5d665a355632d8f79b7b1e951ed2755626ac1151")
        val VECTOR_SHARED_SECRET =
            hex("d4ab9572cd7c68df84854e27a7ddbfc54f89c74cd96d93fa1db660275420153b")

        fun hex(value: String): ByteArray {
            val clean = value.filter { !it.isWhitespace() }
            require(clean.length % 2 == 0)
            return ByteArray(clean.length / 2) { index ->
                clean.substring(index * 2, index * 2 + 2).toInt(16).toByte()
            }
        }
    }
}
