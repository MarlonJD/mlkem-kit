package io.github.marlonjd.mlkemnative

internal object PureKotlinMLKEM768 {
    const val publicKeyBytes = 1184
    const val ciphertextBytes = 1088
    const val sharedSecretBytes = 32
    const val secretKeyBytes = 2400
    const val keypairSeedBytes = 64
    const val encapsulationSeedBytes = 32
    const val incrementalHeaderBytes = 64
    const val encapsulationKeyVectorBytes = 1152
    const val ciphertextPart1Bytes = 960
    const val ciphertextPart2Bytes = 128
    const val incrementalEncapsulationSecretBytes = 64

    private const val n = 256
    private const val k = 3
    private const val q = 3329
    private const val polyBytes = 384
    private const val polyVecBytes = 1152
    private const val eta1 = 2
    private const val eta2 = 2
    private const val polyCompressedBytesDU = 320
    private const val polyVecCompressedBytesDU = 960
    private const val polyCompressedBytesDV = 128
    private const val xofRate = 168

    data class Keypair(
        val publicKey: ByteArray,
        val secretKey: ByteArray,
    )

    data class EncapsulationResult(
        val ciphertext: ByteArray,
        val sharedSecret: ByteArray,
    )

    data class IncrementalPublicKeyParts(
        val header: ByteArray,
        val vector: ByteArray,
    )

    data class IncrementalEncapsulationResult(
        val encapsulationSecret: ByteArray,
        val ciphertextPart1: ByteArray,
        val sharedSecret: ByteArray,
    )

    fun keypairDerand(seed: ByteArray): Keypair {
        if (seed.size != keypairSeedBytes) {
            throw MLKEMException.InvalidPrivateKeyRepresentation()
        }

        val pk = ByteArray(publicKeyBytes)
        val sk = ByteArray(secretKeyBytes)
        val indcpa = indcpaKeypairDerand(seed)
        indcpa.publicKey.copyInto(pk)
        indcpa.secretKey.copyInto(sk)
        pk.copyInto(sk, polyVecBytes)
        sha3_256(pk).copyInto(sk, secretKeyBytes - 64)
        seed.copyInto(
            destination = sk,
            destinationOffset = secretKeyBytes - 32,
            startIndex = 32,
            endIndex = 64,
        )
        return Keypair(pk, sk)
    }

    fun encapsulateDerand(publicKey: ByteArray, seed: ByteArray): EncapsulationResult {
        if (publicKey.size != publicKeyBytes || !checkPublicKey(publicKey)) {
            throw MLKEMException.InvalidPublicKey()
        }
        if (seed.size != encapsulationSeedBytes) {
            throw MLKEMException.OperationFailed("Invalid ML-KEM-768 encapsulation seed")
        }

        val buf = seed + sha3_256(publicKey)
        val kr = sha3_512(buf)
        val ct = indcpaEnc(
            message = buf.copyOfRange(0, 32),
            publicKey = publicKey,
            coins = kr.copyOfRange(32, 64),
        )
        return EncapsulationResult(ct, kr.copyOfRange(0, 32))
    }

    fun decapsulate(ciphertext: ByteArray, secretKey: ByteArray): ByteArray {
        if (ciphertext.size != ciphertextBytes) {
            throw MLKEMException.InvalidCiphertext()
        }
        if (secretKey.size != secretKeyBytes || !checkSecretKey(secretKey)) {
            throw MLKEMException.InvalidPrivateKeyRepresentation()
        }

        val buf = indcpaDec(
            ciphertext = ciphertext,
            secretKey = secretKey.copyOfRange(0, polyVecBytes),
        ) + secretKey.copyOfRange(secretKeyBytes - 64, secretKeyBytes - 32)
        val kr = sha3_512(buf)
        val pk = secretKey.copyOfRange(polyVecBytes, polyVecBytes + publicKeyBytes)
        val cmp = indcpaEnc(
            message = buf.copyOfRange(0, 32),
            publicKey = pk,
            coins = kr.copyOfRange(32, 64),
        )
        val fail = !constantTimeCompare(ciphertext, cmp)

        val rejectionInput = secretKey.copyOfRange(secretKeyBytes - 32, secretKeyBytes) + ciphertext
        val ss = shake256(rejectionInput, outputByteCount = 32)
        val mask = if (fail) 0 else 0xff
        for (i in 0 until 32) {
            ss[i] = ((ss[i].u8() and (mask.inv() and 0xff)) or (kr[i].u8() and mask)).toByte()
        }
        return ss
    }

    fun checkPublicKey(publicKey: ByteArray): Boolean {
        if (publicKey.size != publicKeyBytes) return false
        val pv = polyVecFromBytes(publicKey.copyOfRange(0, polyVecBytes))
        polyVecReduce(pv)
        return constantTimeCompare(
            publicKey.copyOfRange(0, polyVecBytes),
            polyVecToBytes(pv),
        )
    }

    fun checkSecretKey(secretKey: ByteArray): Boolean {
        if (secretKey.size != secretKeyBytes) return false
        val pk = secretKey.copyOfRange(polyVecBytes, polyVecBytes + publicKeyBytes)
        val h = sha3_256(pk)
        return constantTimeCompare(
            secretKey.copyOfRange(secretKeyBytes - 64, secretKeyBytes - 32),
            h,
        )
    }

    fun publicKeyToIncremental(publicKey: ByteArray): IncrementalPublicKeyParts {
        if (publicKey.size != publicKeyBytes || !checkPublicKey(publicKey)) {
            throw MLKEMException.InvalidPublicKey()
        }
        val vector = publicKey.copyOfRange(0, encapsulationKeyVectorBytes)
        val seed = publicKey.copyOfRange(encapsulationKeyVectorBytes, publicKeyBytes)
        return IncrementalPublicKeyParts(seed + sha3_256(publicKey), vector)
    }

    fun publicKeyFromIncremental(header: ByteArray, vector: ByteArray): ByteArray {
        if (header.size != incrementalHeaderBytes || vector.size != encapsulationKeyVectorBytes) {
            throw MLKEMException.InvalidPublicKey()
        }

        val pk = vector + header.copyOfRange(0, 32)
        val expectedHash = sha3_256(pk)
        if (!constantTimeCompare(expectedHash, header.copyOfRange(32, 64)) || !checkPublicKey(pk)) {
            throw MLKEMException.InvalidPublicKey()
        }
        return pk
    }

    fun encapsulatePart1Derand(header: ByteArray, seed: ByteArray): IncrementalEncapsulationResult {
        if (header.size != incrementalHeaderBytes) {
            throw MLKEMException.InvalidPublicKey()
        }
        if (seed.size != encapsulationSeedBytes) {
            throw MLKEMException.OperationFailed("Invalid ML-KEM-768 encapsulation seed")
        }

        val encapsulationSecret = seed + header.copyOfRange(32, 64)
        val kr = sha3_512(encapsulationSecret)
        val sharedSecret = kr.copyOfRange(0, 32)
        kr.copyInto(encapsulationSecret, 32, 32, 64)

        val dummyPublicKey = ByteArray(publicKeyBytes)
        header.copyInto(
            destination = dummyPublicKey,
            destinationOffset = encapsulationKeyVectorBytes,
            startIndex = 0,
            endIndex = 32,
        )
        val ct = indcpaEnc(
            message = encapsulationSecret.copyOfRange(0, 32),
            publicKey = dummyPublicKey,
            coins = encapsulationSecret.copyOfRange(32, 64),
        )
        return IncrementalEncapsulationResult(
            encapsulationSecret = encapsulationSecret,
            ciphertextPart1 = ct.copyOfRange(0, ciphertextPart1Bytes),
            sharedSecret = sharedSecret,
        )
    }

    fun encapsulatePart2(
        encapsulationSecret: ByteArray,
        header: ByteArray,
        vector: ByteArray,
    ): ByteArray {
        val publicKey = publicKeyFromIncremental(header, vector)
        return encapsulatePart2(encapsulationSecret, publicKey)
    }

    fun encapsulatePart2(encapsulationSecret: ByteArray, publicKey: ByteArray): ByteArray {
        if (encapsulationSecret.size != incrementalEncapsulationSecretBytes) {
            throw MLKEMException.InvalidIncrementalEncapsulationSecret()
        }
        if (publicKey.size != publicKeyBytes || !checkPublicKey(publicKey)) {
            throw MLKEMException.InvalidPublicKey()
        }

        val ct = indcpaEnc(
            message = encapsulationSecret.copyOfRange(0, 32),
            publicKey = publicKey,
            coins = encapsulationSecret.copyOfRange(32, 64),
        )
        return ct.copyOfRange(ciphertextPart1Bytes, ciphertextBytes)
    }

    fun decapsulateParts(
        ciphertextPart1: ByteArray,
        ciphertextPart2: ByteArray,
        secretKey: ByteArray,
    ): ByteArray {
        if (ciphertextPart1.size != ciphertextPart1Bytes ||
            ciphertextPart2.size != ciphertextPart2Bytes
        ) {
            throw MLKEMException.InvalidCiphertext()
        }
        return decapsulate(ciphertextPart1 + ciphertextPart2, secretKey)
    }

    fun sha3256(input: ByteArray): ByteArray = sha3_256(input)

    private fun indcpaKeypairDerand(seed64: ByteArray): Keypair {
        val seedWithDomain = seed64.copyOfRange(0, 32) + byteArrayOf(k.toByte())
        val hashed = sha3_512(seedWithDomain)
        val publicSeed = hashed.copyOfRange(0, 32)
        val noiseSeed = hashed.copyOfRange(32, 64)
        val matrix = genMatrix(seed = publicSeed, transposed = false)

        val skpv = PolyVec()
        val e = PolyVec()
        for (i in 0 until k) {
            skpv.vec[i] = getNoise(eta = eta1, seed = noiseSeed, nonce = i)
            e.vec[i] = getNoise(eta = eta1, seed = noiseSeed, nonce = i + k)
        }

        polyVecNTT(skpv)
        polyVecNTT(e)
        val skpvCache = polyVecMulcacheCompute(skpv)
        val pkpv = PolyVec()
        for (i in 0 until k) {
            pkpv.vec[i] = polyVecBaseMulAcc(matrix[i], skpv, skpvCache)
        }
        polyVecToMont(pkpv)
        polyVecAdd(pkpv, e)
        polyVecReduce(pkpv)
        polyVecReduce(skpv)

        return Keypair(
            publicKey = polyVecToBytes(pkpv) + publicSeed,
            secretKey = polyVecToBytes(skpv),
        )
    }

    private fun indcpaEnc(message: ByteArray, publicKey: ByteArray, coins: ByteArray): ByteArray {
        val pkpv = polyVecFromBytes(publicKey.copyOfRange(0, polyVecBytes))
        val seed = publicKey.copyOfRange(polyVecBytes, publicKeyBytes)
        val kpoly = polyFromMessage(message)
        val at = genMatrix(seed = seed, transposed = true)

        val sp = PolyVec()
        val ep = PolyVec()
        for (i in 0 until k) {
            sp.vec[i] = getNoise(eta = eta1, seed = coins, nonce = i)
            ep.vec[i] = getNoise(eta = eta2, seed = coins, nonce = i + k)
        }
        val epp = getNoise(eta = eta2, seed = coins, nonce = 2 * k)

        polyVecNTT(sp)
        val spCache = polyVecMulcacheCompute(sp)
        val b = PolyVec()
        for (i in 0 until k) {
            b.vec[i] = polyVecBaseMulAcc(at[i], sp, spCache)
        }
        val v = polyVecBaseMulAcc(pkpv, sp, spCache)

        polyVecInvNTT(b)
        polyInvNTT(v)
        polyVecAdd(b, ep)
        polyAdd(v, epp)
        polyAdd(v, kpoly)
        polyVecReduce(b)
        polyReduce(v)
        return packCiphertext(b = b, v = v)
    }

    private fun indcpaDec(ciphertext: ByteArray, secretKey: ByteArray): ByteArray {
        val unpacked = unpackCiphertext(ciphertext)
        val b = unpacked.first
        val v = unpacked.second
        val skpv = polyVecFromBytes(secretKey)
        polyVecNTT(b)
        val bCache = polyVecMulcacheCompute(b)
        val sb = polyVecBaseMulAcc(skpv, b, bCache)
        polyInvNTT(sb)
        polySub(v, sb)
        polyReduce(v)
        return polyToMessage(v)
    }

    private class Poly(
        val coeffs: IntArray = IntArray(n),
    )

    private class PolyVec(
        val vec: Array<Poly> = Array(k) { Poly() },
    )

    private class PolyMulcache(
        val coeffs: IntArray = IntArray(n / 2),
    )

    private class PolyVecMulcache(
        val vec: Array<PolyMulcache> = Array(k) { PolyMulcache() },
    )

    private fun packCiphertext(b: PolyVec, v: Poly): ByteArray =
        polyVecCompressDU(b) + polyCompressDV(v)

    private fun unpackCiphertext(c: ByteArray): Pair<PolyVec, Poly> =
        polyVecDecompressDU(c.copyOfRange(0, polyVecCompressedBytesDU)) to
            polyDecompressDV(c.copyOfRange(polyVecCompressedBytesDU, ciphertextBytes))

    private fun genMatrix(seed: ByteArray, transposed: Boolean): Array<PolyVec> {
        val matrix = Array(k) { PolyVec() }
        for (row in 0 until k) {
            for (col in 0 until k) {
                val suffix = if (transposed) {
                    byteArrayOf(row.toByte(), col.toByte())
                } else {
                    byteArrayOf(col.toByte(), row.toByte())
                }
                matrix[row].vec[col] = rejUniformPoly(seed + suffix)
            }
        }
        return matrix
    }

    private fun rejUniformPoly(seed: ByteArray): Poly {
        val xof = Shake128XOF(input = seed)
        val out = Poly()
        var ctr = 0
        var buffer = xof.squeezeBlocks(3)
        ctr = rejUniform(out.coeffs, target = n, offset = ctr, buffer = buffer)
        while (ctr < n) {
            buffer = xof.squeezeBlocks(1)
            ctr = rejUniform(out.coeffs, target = n, offset = ctr, buffer = buffer)
        }
        return out
    }

    private fun rejUniform(r: IntArray, target: Int, offset: Int, buffer: ByteArray): Int {
        var ctr = offset
        var pos = 0
        while (ctr < target && pos + 3 <= buffer.size) {
            val val0 = (buffer[pos].u8() or (buffer[pos + 1].u8() shl 8)) and 0x0fff
            val val1 = ((buffer[pos + 1].u8() ushr 4) or (buffer[pos + 2].u8() shl 4)) and 0x0fff
            pos += 3
            if (val0 < q) {
                r[ctr] = val0
                ctr += 1
            }
            if (ctr < target && val1 < q) {
                r[ctr] = val1
                ctr += 1
            }
        }
        return ctr
    }

    private fun getNoise(eta: Int, seed: ByteArray, nonce: Int): Poly {
        val bytes = shake256(seed + byteArrayOf(nonce.toByte()), outputByteCount = eta * n / 4)
        return cbd2(bytes)
    }

    private fun cbd2(buffer: ByteArray): Poly {
        val r = Poly()
        for (i in 0 until n / 8) {
            val t = load32(buffer, 4 * i)
            var d = t and 0x55555555L
            d += (t ushr 1) and 0x55555555L
            for (j in 0 until 8) {
                val a = ((d ushr (4 * j)) and 0x3L).toInt()
                val b = ((d ushr (4 * j + 2)) and 0x3L).toInt()
                r.coeffs[8 * i + j] = a - b
            }
        }
        return r
    }

    private fun load32(bytes: ByteArray, offset: Int): Long =
        bytes[offset].u8().toLong() or
            (bytes[offset + 1].u8().toLong() shl 8) or
            (bytes[offset + 2].u8().toLong() shl 16) or
            (bytes[offset + 3].u8().toLong() shl 24)

    private fun polyVecCompressDU(a: PolyVec): ByteArray {
        val out = ByteArray(polyVecCompressedBytesDU)
        for (i in 0 until k) {
            polyCompressDU(a.vec[i]).copyInto(out, i * polyCompressedBytesDU)
        }
        return out
    }

    private fun polyVecDecompressDU(bytes: ByteArray): PolyVec {
        val out = PolyVec()
        for (i in 0 until k) {
            out.vec[i] = polyDecompressDU(
                bytes.copyOfRange(i * polyCompressedBytesDU, (i + 1) * polyCompressedBytesDU),
            )
        }
        return out
    }

    private fun polyCompressDU(a: Poly): ByteArray {
        val r = ByteArray(polyCompressedBytesDU)
        for (j in 0 until n / 4) {
            val t = IntArray(4)
            for (i in 0 until 4) {
                t[i] = scalarCompressD10(a.coeffs[4 * j + i])
            }
            r[5 * j + 0] = t[0].toByteTrunc()
            r[5 * j + 1] = ((t[0] ushr 8) or ((t[1] shl 2) and 0xff)).toByteTrunc()
            r[5 * j + 2] = ((t[1] ushr 6) or ((t[2] shl 4) and 0xff)).toByteTrunc()
            r[5 * j + 3] = ((t[2] ushr 4) or ((t[3] shl 6) and 0xff)).toByteTrunc()
            r[5 * j + 4] = (t[3] ushr 2).toByteTrunc()
        }
        return r
    }

    private fun polyDecompressDU(bytes: ByteArray): Poly {
        val r = Poly()
        for (j in 0 until n / 4) {
            val base = 5 * j
            val t0 = bytes[base].u8() or (bytes[base + 1].u8() shl 8)
            val t1 = (bytes[base + 1].u8() ushr 2) or (bytes[base + 2].u8() shl 6)
            val t2 = (bytes[base + 2].u8() ushr 4) or (bytes[base + 3].u8() shl 4)
            val t3 = (bytes[base + 3].u8() ushr 6) or (bytes[base + 4].u8() shl 2)
            r.coeffs[4 * j + 0] = scalarDecompressD10(t0 and 0x03ff)
            r.coeffs[4 * j + 1] = scalarDecompressD10(t1 and 0x03ff)
            r.coeffs[4 * j + 2] = scalarDecompressD10(t2 and 0x03ff)
            r.coeffs[4 * j + 3] = scalarDecompressD10(t3 and 0x03ff)
        }
        return r
    }

    private fun polyCompressDV(a: Poly): ByteArray {
        val r = ByteArray(polyCompressedBytesDV)
        for (i in 0 until n / 8) {
            val t = IntArray(8)
            for (j in 0 until 8) {
                t[j] = scalarCompressD4(a.coeffs[8 * i + j])
            }
            r[4 * i + 0] = (t[0] or (t[1] shl 4)).toByteTrunc()
            r[4 * i + 1] = (t[2] or (t[3] shl 4)).toByteTrunc()
            r[4 * i + 2] = (t[4] or (t[5] shl 4)).toByteTrunc()
            r[4 * i + 3] = (t[6] or (t[7] shl 4)).toByteTrunc()
        }
        return r
    }

    private fun polyDecompressDV(bytes: ByteArray): Poly {
        val r = Poly()
        for (i in 0 until n / 2) {
            r.coeffs[2 * i + 0] = scalarDecompressD4(bytes[i].u8() and 0x0f)
            r.coeffs[2 * i + 1] = scalarDecompressD4((bytes[i].u8() ushr 4) and 0x0f)
        }
        return r
    }

    private fun scalarCompressD1(u: Int): Int {
        val d0 = ((u and 0xffff).toLong() * 1_290_168L) and 0xffffffffL
        return (((d0 + (1L shl 30)) and 0xffffffffL) ushr 31).toInt()
    }

    private fun scalarCompressD4(u: Int): Int {
        val d0 = ((u and 0xffff).toLong() * 1_290_160L) and 0xffffffffL
        return (((d0 + (1L shl 27)) and 0xffffffffL) ushr 28).toInt()
    }

    private fun scalarDecompressD4(u: Int): Int =
        ((u * q) + 8) ushr 4

    private fun scalarCompressD10(u: Int): Int {
        var d0 = (u and 0xffff).toLong() * 2_642_263_040L
        d0 = (d0 + (1L shl 32)) ushr 33
        return (d0 and 0x03ffL).toInt()
    }

    private fun scalarDecompressD10(u: Int): Int =
        ((u * q) + 512) ushr 10

    private fun polyVecToBytes(a: PolyVec): ByteArray {
        val out = ByteArray(polyVecBytes)
        for (i in 0 until k) {
            polyToBytes(a.vec[i]).copyInto(out, i * polyBytes)
        }
        return out
    }

    private fun polyVecFromBytes(bytes: ByteArray): PolyVec {
        val r = PolyVec()
        for (i in 0 until k) {
            r.vec[i] = polyFromBytes(bytes.copyOfRange(i * polyBytes, (i + 1) * polyBytes))
        }
        return r
    }

    private fun polyToBytes(a: Poly): ByteArray {
        val r = ByteArray(polyBytes)
        for (i in 0 until n / 2) {
            val t0 = a.coeffs[2 * i] and 0xffff
            val t1 = a.coeffs[2 * i + 1] and 0xffff
            r[3 * i + 0] = t0.toByteTrunc()
            r[3 * i + 1] = ((t0 ushr 8) or (t1 shl 4)).toByteTrunc()
            r[3 * i + 2] = (t1 ushr 4).toByteTrunc()
        }
        return r
    }

    private fun polyFromBytes(bytes: ByteArray): Poly {
        val r = Poly()
        for (i in 0 until n / 2) {
            val b0 = bytes[3 * i].u8()
            val b1 = bytes[3 * i + 1].u8()
            val b2 = bytes[3 * i + 2].u8()
            r.coeffs[2 * i + 0] = (b0 or (b1 shl 8)) and 0x0fff
            r.coeffs[2 * i + 1] = ((b1 ushr 4) or (b2 shl 4)) and 0x0fff
        }
        return r
    }

    private fun polyFromMessage(message: ByteArray): Poly {
        val r = Poly()
        for (i in 0 until 32) {
            for (j in 0 until 8) {
                val bit = (message[i].u8() ushr j) and 1
                r.coeffs[8 * i + j] = if (bit == 1) 1665 else 0
            }
        }
        return r
    }

    private fun polyToMessage(a: Poly): ByteArray {
        val msg = ByteArray(32)
        for (i in 0 until 32) {
            for (j in 0 until 8) {
                msg[i] = (msg[i].u8() or (scalarCompressD1(a.coeffs[8 * i + j]) shl j)).toByte()
            }
        }
        return msg
    }

    private fun polyVecNTT(v: PolyVec) {
        for (i in 0 until k) {
            polyNTT(v.vec[i])
        }
    }

    private fun polyVecInvNTT(v: PolyVec) {
        for (i in 0 until k) {
            polyInvNTT(v.vec[i])
        }
    }

    private fun polyVecToMont(v: PolyVec) {
        for (i in 0 until k) {
            polyToMont(v.vec[i])
        }
    }

    private fun polyVecReduce(v: PolyVec) {
        for (i in 0 until k) {
            polyReduce(v.vec[i])
        }
    }

    private fun polyVecAdd(v: PolyVec, b: PolyVec) {
        for (i in 0 until k) {
            polyAdd(v.vec[i], b.vec[i])
        }
    }

    private fun polyAdd(r: Poly, b: Poly) {
        for (i in 0 until n) {
            r.coeffs[i] += b.coeffs[i]
        }
    }

    private fun polySub(r: Poly, b: Poly) {
        for (i in 0 until n) {
            r.coeffs[i] -= b.coeffs[i]
        }
    }

    private fun polyReduce(r: Poly) {
        for (i in 0 until n) {
            val t = barrettReduce(r.coeffs[i])
            r.coeffs[i] = if (t < 0) t + q else t
        }
    }

    private fun polyToMont(r: Poly) {
        for (i in 0 until n) {
            r.coeffs[i] = fqmul(r.coeffs[i], 1353)
        }
    }

    private fun polyNTT(p: Poly) {
        for (layer in 1..7) {
            var zetaIndex = 1 shl (layer - 1)
            val len = n shr layer
            var start = 0
            while (start < n) {
                val zeta = zetas[zetaIndex]
                zetaIndex += 1
                for (j in start until start + len) {
                    val t = fqmul(p.coeffs[j + len], zeta)
                    p.coeffs[j + len] = p.coeffs[j] - t
                    p.coeffs[j] += t
                }
                start += 2 * len
            }
        }
    }

    private fun polyInvNTT(p: Poly) {
        for (j in 0 until n) {
            p.coeffs[j] = fqmul(p.coeffs[j], 1441)
        }
        for (layer in 7 downTo 1) {
            val len = n shr layer
            var zetaIndex = (1 shl layer) - 1
            var start = 0
            while (start < n) {
                val zeta = zetas[zetaIndex]
                zetaIndex -= 1
                for (j in start until start + len) {
                    val t = p.coeffs[j]
                    p.coeffs[j] = barrettReduce(t + p.coeffs[j + len])
                    p.coeffs[j + len] -= t
                    p.coeffs[j + len] = fqmul(p.coeffs[j + len], zeta)
                }
                start += 2 * len
            }
        }
    }

    private fun polyVecMulcacheCompute(v: PolyVec): PolyVecMulcache {
        val cache = PolyVecMulcache()
        for (i in 0 until k) {
            cache.vec[i] = polyMulcacheCompute(v.vec[i])
        }
        return cache
    }

    private fun polyMulcacheCompute(a: Poly): PolyMulcache {
        val cache = PolyMulcache()
        for (i in 0 until n / 4) {
            cache.coeffs[2 * i + 0] = fqmul(a.coeffs[4 * i + 1], zetas[64 + i])
            cache.coeffs[2 * i + 1] = fqmul(a.coeffs[4 * i + 3], -zetas[64 + i])
        }
        return cache
    }

    private fun polyVecBaseMulAcc(a: PolyVec, b: PolyVec, bCache: PolyVecMulcache): Poly {
        val r = Poly()
        for (i in 0 until n / 2) {
            var t0 = 0
            var t1 = 0
            for (j in 0 until k) {
                t0 += a.vec[j].coeffs[2 * i + 1] * bCache.vec[j].coeffs[i]
                t0 += a.vec[j].coeffs[2 * i] * b.vec[j].coeffs[2 * i]
                t1 += a.vec[j].coeffs[2 * i] * b.vec[j].coeffs[2 * i + 1]
                t1 += a.vec[j].coeffs[2 * i + 1] * b.vec[j].coeffs[2 * i]
            }
            r.coeffs[2 * i] = montgomeryReduce(t0)
            r.coeffs[2 * i + 1] = montgomeryReduce(t1)
        }
        return r
    }

    private fun fqmul(a: Int, b: Int): Int =
        montgomeryReduce(a * b)

    private fun montgomeryReduce(a: Int): Int {
        val aReduced = a and 0xffff
        val aInverted = (aReduced * 62209) and 0xffff
        val t = if (aInverted >= 0x8000) aInverted - 0x10000 else aInverted
        return (a - t * q) shr 16
    }

    private fun barrettReduce(a: Int): Int {
        val t = (20159 * a + (1 shl 25)) shr 26
        return a - t * q
    }

    private fun constantTimeCompare(lhs: ByteArray, rhs: ByteArray): Boolean {
        if (lhs.size != rhs.size) return false
        var diff = 0
        for (i in lhs.indices) {
            diff = diff or (lhs[i].u8() xor rhs[i].u8())
        }
        return diff == 0
    }

    private fun sha3_256(input: ByteArray): ByteArray =
        Keccak.hash(input, outputByteCount = 32, rate = 136, domain = 0x06)

    private fun sha3_512(input: ByteArray): ByteArray =
        Keccak.hash(input, outputByteCount = 64, rate = 72, domain = 0x06)

    private fun shake256(input: ByteArray, outputByteCount: Int): ByteArray =
        Keccak.hash(input, outputByteCount = outputByteCount, rate = 136, domain = 0x1f)

    private class Shake128XOF(input: ByteArray) {
        private val state = Keccak.absorb(input, rate = xofRate, domain = 0x1f)

        fun squeezeBlocks(blockCount: Int): ByteArray {
            val out = ByteArray(blockCount * xofRate)
            var offset = 0
            repeat(blockCount) {
                Keccak.permute(state)
                Keccak.extractBytes(state, sourceOffset = 0, count = xofRate)
                    .copyInto(out, offset)
                offset += xofRate
            }
            return out
        }
    }

    private object Keccak {
        fun hash(input: ByteArray, outputByteCount: Int, rate: Int, domain: Int): ByteArray {
            val state = absorb(input, rate = rate, domain = domain)
            val out = ByteArray(outputByteCount)
            var offset = 0
            while (offset < outputByteCount) {
                permute(state)
                val count = minOf(rate, outputByteCount - offset)
                extractBytes(state, sourceOffset = 0, count = count).copyInto(out, offset)
                offset += count
            }
            return out
        }

        fun absorb(input: ByteArray, rate: Int, domain: Int): LongArray {
            val state = LongArray(25)
            var offset = 0
            var remaining = input.size
            while (remaining >= rate) {
                xorBytes(state, input, inputOffset = offset, stateOffset = 0, count = rate)
                permute(state)
                offset += rate
                remaining -= rate
            }
            if (remaining > 0) {
                xorBytes(state, input, inputOffset = offset, stateOffset = 0, count = remaining)
            }
            xorByte(state, domain, offset = remaining)
            xorByte(state, 0x80, offset = rate - 1)
            return state
        }

        private fun xorBytes(
            state: LongArray,
            input: ByteArray,
            inputOffset: Int,
            stateOffset: Int,
            count: Int,
        ) {
            for (i in 0 until count) {
                xorByte(state, input[inputOffset + i].u8(), offset = stateOffset + i)
            }
        }

        private fun xorByte(state: LongArray, byte: Int, offset: Int) {
            val lane = offset / 8
            val shift = (offset % 8) * 8
            state[lane] = state[lane] xor (byte.toLong() shl shift)
        }

        fun extractBytes(state: LongArray, sourceOffset: Int, count: Int): ByteArray {
            val out = ByteArray(count)
            for (i in 0 until count) {
                val byteOffset = sourceOffset + i
                val lane = byteOffset / 8
                val shift = (byteOffset % 8) * 8
                out[i] = ((state[lane] ushr shift) and 0xffL).toByte()
            }
            return out
        }

        fun permute(state: LongArray) {
            for (round in 0 until 24) {
                val c = LongArray(5)
                val d = LongArray(5)
                for (x in 0 until 5) {
                    c[x] = state[x] xor state[x + 5] xor state[x + 10] xor
                        state[x + 15] xor state[x + 20]
                }
                for (x in 0 until 5) {
                    d[x] = c[(x + 4) % 5] xor java.lang.Long.rotateLeft(c[(x + 1) % 5], 1)
                }
                for (x in 0 until 5) {
                    for (y in 0 until 5) {
                        state[x + 5 * y] = state[x + 5 * y] xor d[x]
                    }
                }

                val b = LongArray(25)
                for (x in 0 until 5) {
                    for (y in 0 until 5) {
                        val index = x + 5 * y
                        b[y + 5 * ((2 * x + 3 * y) % 5)] =
                            java.lang.Long.rotateLeft(state[index], rho[index])
                    }
                }

                for (x in 0 until 5) {
                    for (y in 0 until 5) {
                        state[x + 5 * y] = b[x + 5 * y] xor
                            (b[((x + 1) % 5) + 5 * y].inv() and b[((x + 2) % 5) + 5 * y])
                    }
                }
                state[0] = state[0] xor roundConstants[round]
            }
        }

        private val rho = intArrayOf(
            0, 1, 62, 28, 27,
            36, 44, 6, 55, 20,
            3, 10, 43, 25, 39,
            41, 45, 15, 21, 8,
            18, 2, 61, 56, 14,
        )

        private val roundConstants = longArrayOf(
            0x0000000000000001L, 0x0000000000008082L,
            0x800000000000808aUL.toLong(), 0x8000000080008000UL.toLong(),
            0x000000000000808bL, 0x0000000080000001L,
            0x8000000080008081UL.toLong(), 0x8000000000008009UL.toLong(),
            0x000000000000008aL, 0x0000000000000088L,
            0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bUL.toLong(),
            0x8000000000008089UL.toLong(), 0x8000000000008003UL.toLong(),
            0x8000000000008002UL.toLong(), 0x8000000000000080UL.toLong(),
            0x000000000000800aL, 0x800000008000000aUL.toLong(),
            0x8000000080008081UL.toLong(), 0x8000000000008080UL.toLong(),
            0x0000000080000001L, 0x8000000080008008UL.toLong(),
        )
    }

    private val zetas = intArrayOf(
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
    )

    private fun Byte.u8(): Int = toInt() and 0xff

    private fun Int.toByteTrunc(): Byte = (this and 0xff).toByte()
}
