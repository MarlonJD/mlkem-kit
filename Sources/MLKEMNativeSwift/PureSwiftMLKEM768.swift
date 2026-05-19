import Foundation

enum PureSwiftMLKEM768 {
    static let publicKeyBytes = 1184
    static let ciphertextBytes = 1088
    static let sharedSecretBytes = 32
    static let secretKeyBytes = 2400
    static let keypairSeedBytes = 64
    static let encapsulationSeedBytes = 32
    static let incrementalHeaderBytes = 64
    static let encapsulationKeyVectorBytes = 1152
    static let ciphertextPart1Bytes = 960
    static let ciphertextPart2Bytes = 128
    static let incrementalEncapsulationSecretBytes = 64

    private static let n = 256
    private static let k = 3
    private static let q: Int16 = 3329
    private static let qInt = 3329
    private static let symBytes = 32
    private static let polyBytes = 384
    private static let polyVecBytes = 1152
    private static let eta1 = 2
    private static let eta2 = 2
    private static let polyCompressedBytesDU = 320
    private static let polyVecCompressedBytesDU = 960
    private static let polyCompressedBytesDV = 128
    private static let xofRate = 168

    struct IncrementalEncapsulationResult {
        let encapsulationSecret: Data
        let ciphertextPart1: Data
        let sharedSecret: Data
    }

    static func keypairDerand(seed: Data) throws -> (publicKey: Data, secretKey: Data) {
        guard seed.count == keypairSeedBytes else { throw MLKEMError.invalidPrivateKeyRepresentation }
        var pk = [UInt8](repeating: 0, count: publicKeyBytes)
        var sk = [UInt8](repeating: 0, count: secretKeyBytes)
        let (indcpaPk, indcpaSk) = indcpaKeypairDerand([UInt8](seed))
        pk.replaceSubrange(0..<publicKeyBytes, with: indcpaPk)
        sk.replaceSubrange(0..<polyVecBytes, with: indcpaSk)
        sk.replaceSubrange(polyVecBytes..<(polyVecBytes + publicKeyBytes), with: pk)
        sk.replaceSubrange((secretKeyBytes - 64)..<(secretKeyBytes - 32), with: sha3_256(pk))
        sk.replaceSubrange((secretKeyBytes - 32)..<secretKeyBytes, with: seed[32..<64])
        return (Data(pk), Data(sk))
    }

    static func encapsulateDerand(publicKey: Data, seed: Data) throws -> (ciphertext: Data, sharedSecret: Data) {
        guard publicKey.count == publicKeyBytes else { throw MLKEMError.invalidPublicKey }
        guard seed.count == encapsulationSeedBytes else { throw MLKEMError.operationFailed }
        let pk = [UInt8](publicKey)
        guard checkPublicKey(pk) else { throw MLKEMError.invalidPublicKey }

        var buf = [UInt8](seed)
        buf += sha3_256(pk)
        let kr = sha3_512(buf)
        let ct = indcpaEnc(message: Array(buf[0..<32]), publicKey: pk, coins: Array(kr[32..<64]))
        return (Data(ct), Data(kr[0..<32]))
    }

    static func decapsulate(ciphertext: Data, secretKey: Data) throws -> Data {
        guard ciphertext.count == ciphertextBytes else { throw MLKEMError.invalidCiphertext }
        guard secretKey.count == secretKeyBytes else { throw MLKEMError.invalidPrivateKeyRepresentation }
        let ct = [UInt8](ciphertext)
        let sk = [UInt8](secretKey)
        guard checkSecretKey(sk) else { throw MLKEMError.invalidPrivateKeyRepresentation }

        var buf = indcpaDec(ciphertext: ct, secretKey: Array(sk[0..<polyVecBytes]))
        buf += sk[(secretKeyBytes - 64)..<(secretKeyBytes - 32)]
        let kr = sha3_512(buf)
        let pk = Array(sk[polyVecBytes..<(polyVecBytes + publicKeyBytes)])
        let cmp = indcpaEnc(message: Array(buf[0..<32]), publicKey: pk, coins: Array(kr[32..<64]))
        let fail = constantTimeCompare(ct, cmp) == false

        let rejectionInput = Array(sk[(secretKeyBytes - 32)..<secretKeyBytes]) + ct
        var ss = shake256(rejectionInput, outputByteCount: 32)
        let mask: UInt8 = fail ? 0 : 0xff
        for i in 0..<32 {
            ss[i] = (ss[i] & ~mask) | (kr[i] & mask)
        }
        return Data(ss)
    }

    static func checkPublicKey(_ pk: Data) -> Bool {
        guard pk.count == publicKeyBytes else { return false }
        return checkPublicKey([UInt8](pk))
    }

    static func publicKeyToIncremental(_ publicKey: Data) throws -> (header: Data, vector: Data) {
        guard publicKey.count == publicKeyBytes else { throw MLKEMError.invalidPublicKey }
        let pk = [UInt8](publicKey)
        guard checkPublicKey(pk) else { throw MLKEMError.invalidPublicKey }
        let vector = Array(pk[0..<encapsulationKeyVectorBytes])
        let seed = Array(pk[encapsulationKeyVectorBytes..<publicKeyBytes])
        return (Data(seed + sha3_256(pk)), Data(vector))
    }

    static func publicKeyFromIncremental(header: Data, vector: Data) throws -> Data {
        guard header.count == incrementalHeaderBytes,
              vector.count == encapsulationKeyVectorBytes else {
            throw MLKEMError.invalidPublicKey
        }
        let headerBytes = [UInt8](header)
        let pk = [UInt8](vector) + Array(headerBytes[0..<32])
        let expectedHash = sha3_256(pk)
        guard constantTimeCompare(expectedHash, Array(headerBytes[32..<64])),
              checkPublicKey(pk) else {
            throw MLKEMError.invalidPublicKey
        }
        return Data(pk)
    }

    static func encapsulatePart1Derand(header: Data, seed: Data) throws -> IncrementalEncapsulationResult {
        guard header.count == incrementalHeaderBytes else { throw MLKEMError.invalidPublicKey }
        guard seed.count == encapsulationSeedBytes else { throw MLKEMError.operationFailed }
        let headerBytes = [UInt8](header)
        var encapsulationSecret = [UInt8](seed) + Array(headerBytes[32..<64])
        let kr = sha3_512(encapsulationSecret)
        let sharedSecret = Array(kr[0..<32])
        encapsulationSecret.replaceSubrange(32..<64, with: kr[32..<64])

        var dummyPublicKey = [UInt8](repeating: 0, count: publicKeyBytes)
        dummyPublicKey.replaceSubrange(encapsulationKeyVectorBytes..<publicKeyBytes, with: headerBytes[0..<32])
        let ct = indcpaEnc(message: Array(encapsulationSecret[0..<32]), publicKey: dummyPublicKey, coins: Array(encapsulationSecret[32..<64]))
        return IncrementalEncapsulationResult(
            encapsulationSecret: Data(encapsulationSecret),
            ciphertextPart1: Data(ct[0..<ciphertextPart1Bytes]),
            sharedSecret: Data(sharedSecret)
        )
    }

    static func encapsulatePart2(encapsulationSecret: Data, header: Data, vector: Data) throws -> Data {
        guard encapsulationSecret.count == incrementalEncapsulationSecretBytes else { throw MLKEMError.operationFailed }
        let pk = try publicKeyFromIncremental(header: header, vector: vector)
        let secret = [UInt8](encapsulationSecret)
        let ct = indcpaEnc(message: Array(secret[0..<32]), publicKey: [UInt8](pk), coins: Array(secret[32..<64]))
        return Data(ct[ciphertextPart1Bytes..<ciphertextBytes])
    }

    static func decapsulateParts(ciphertextPart1: Data, ciphertextPart2: Data, secretKey: Data) throws -> Data {
        guard ciphertextPart1.count == ciphertextPart1Bytes,
              ciphertextPart2.count == ciphertextPart2Bytes else {
            throw MLKEMError.invalidCiphertext
        }
        return try decapsulate(ciphertext: ciphertextPart1 + ciphertextPart2, secretKey: secretKey)
    }

    private static func checkPublicKey(_ pk: [UInt8]) -> Bool {
        guard pk.count == publicKeyBytes else { return false }
        var pv = polyVecFromBytes(Array(pk[0..<polyVecBytes]))
        polyVecReduce(&pv)
        return constantTimeCompare(Array(pk[0..<polyVecBytes]), polyVecToBytes(pv))
    }

    private static func checkSecretKey(_ sk: [UInt8]) -> Bool {
        guard sk.count == secretKeyBytes else { return false }
        let pk = Array(sk[polyVecBytes..<(polyVecBytes + publicKeyBytes)])
        let h = sha3_256(pk)
        return constantTimeCompare(Array(sk[(secretKeyBytes - 64)..<(secretKeyBytes - 32)]), h)
    }

    private static func indcpaKeypairDerand(_ seed64: [UInt8]) -> (publicKey: [UInt8], secretKey: [UInt8]) {
        let seedWithDomain = Array(seed64[0..<32]) + [UInt8(k)]
        let hashed = sha3_512(seedWithDomain)
        let publicSeed = Array(hashed[0..<32])
        let noiseSeed = Array(hashed[32..<64])
        let matrix = genMatrix(seed: publicSeed, transposed: false)

        var skpv = PolyVec()
        var e = PolyVec()
        for i in 0..<k {
            skpv.vec[i] = getNoise(eta: eta1, seed: noiseSeed, nonce: UInt8(i))
            e.vec[i] = getNoise(eta: eta1, seed: noiseSeed, nonce: UInt8(i + k))
        }

        polyVecNTT(&skpv)
        polyVecNTT(&e)
        let skpvCache = polyVecMulcacheCompute(skpv)
        var pkpv = PolyVec()
        for i in 0..<k {
            pkpv.vec[i] = polyVecBaseMulAcc(matrix[i], skpv, skpvCache)
        }
        polyVecToMont(&pkpv)
        polyVecAdd(&pkpv, e)
        polyVecReduce(&pkpv)
        polyVecReduce(&skpv)

        let publicKey = polyVecToBytes(pkpv) + publicSeed
        let secretKey = polyVecToBytes(skpv)
        return (publicKey, secretKey)
    }

    private static func indcpaEnc(message: [UInt8], publicKey: [UInt8], coins: [UInt8]) -> [UInt8] {
        let pkpv = polyVecFromBytes(Array(publicKey[0..<polyVecBytes]))
        let seed = Array(publicKey[polyVecBytes..<publicKeyBytes])
        let kpoly = polyFromMessage(message)
        let at = genMatrix(seed: seed, transposed: true)

        var sp = PolyVec()
        var ep = PolyVec()
        for i in 0..<k {
            sp.vec[i] = getNoise(eta: eta1, seed: coins, nonce: UInt8(i))
            ep.vec[i] = getNoise(eta: eta2, seed: coins, nonce: UInt8(i + k))
        }
        let epp = getNoise(eta: eta2, seed: coins, nonce: UInt8(2 * k))

        polyVecNTT(&sp)
        let spCache = polyVecMulcacheCompute(sp)
        var b = PolyVec()
        for i in 0..<k {
            b.vec[i] = polyVecBaseMulAcc(at[i], sp, spCache)
        }
        var v = polyVecBaseMulAcc(pkpv, sp, spCache)

        polyVecInvNTT(&b)
        polyInvNTT(&v)
        polyVecAdd(&b, ep)
        polyAdd(&v, epp)
        polyAdd(&v, kpoly)
        polyVecReduce(&b)
        polyReduce(&v)
        return packCiphertext(b: b, v: v)
    }

    private static func indcpaDec(ciphertext: [UInt8], secretKey: [UInt8]) -> [UInt8] {
        var (b, v) = unpackCiphertext(ciphertext)
        let skpv = polyVecFromBytes(secretKey)
        polyVecNTT(&b)
        let bCache = polyVecMulcacheCompute(b)
        var sb = polyVecBaseMulAcc(skpv, b, bCache)
        polyInvNTT(&sb)
        polySub(&v, sb)
        polyReduce(&v)
        return polyToMessage(v)
    }

    private struct Poly {
        var coeffs: [Int16] = [Int16](repeating: 0, count: n)
    }

    private struct PolyVec {
        var vec: [Poly] = [Poly](repeating: Poly(), count: k)
    }

    private struct PolyMulcache {
        var coeffs: [Int16] = [Int16](repeating: 0, count: n / 2)
    }

    private struct PolyVecMulcache {
        var vec: [PolyMulcache] = [PolyMulcache](repeating: PolyMulcache(), count: k)
    }

    private static func packCiphertext(b: PolyVec, v: Poly) -> [UInt8] {
        polyVecCompressDU(b) + polyCompressDV(v)
    }

    private static func unpackCiphertext(_ c: [UInt8]) -> (PolyVec, Poly) {
        (
            polyVecDecompressDU(Array(c[0..<polyVecCompressedBytesDU])),
            polyDecompressDV(Array(c[polyVecCompressedBytesDU..<ciphertextBytes]))
        )
    }

    private static func genMatrix(seed: [UInt8], transposed: Bool) -> [PolyVec] {
        var matrix = [PolyVec](repeating: PolyVec(), count: k)
        for row in 0..<k {
            for col in 0..<k {
                let suffix: [UInt8] = transposed ? [UInt8(row), UInt8(col)] : [UInt8(col), UInt8(row)]
                matrix[row].vec[col] = rejUniformPoly(seed + suffix)
            }
        }
        return matrix
    }

    private static func rejUniformPoly(_ seed: [UInt8]) -> Poly {
        var xof = Shake128XOF(input: seed)
        var out = Poly()
        var ctr = 0
        var buffer = xof.squeezeBlocks(3)
        ctr = rejUniform(&out.coeffs, target: n, offset: ctr, buffer: buffer)
        while ctr < n {
            buffer = xof.squeezeBlocks(1)
            ctr = rejUniform(&out.coeffs, target: n, offset: ctr, buffer: buffer)
        }
        return out
    }

    private static func rejUniform(_ r: inout [Int16], target: Int, offset: Int, buffer: [UInt8]) -> Int {
        var ctr = offset
        var pos = 0
        while ctr < target && pos + 3 <= buffer.count {
            let val0 = Int16(((UInt16(buffer[pos]) | (UInt16(buffer[pos + 1]) << 8)) & 0x0fff))
            let val1 = Int16((((UInt16(buffer[pos + 1]) >> 4) | (UInt16(buffer[pos + 2]) << 4)) & 0x0fff))
            pos += 3
            if val0 < q {
                r[ctr] = val0
                ctr += 1
            }
            if ctr < target && val1 < q {
                r[ctr] = val1
                ctr += 1
            }
        }
        return ctr
    }

    private static func getNoise(eta: Int, seed: [UInt8], nonce: UInt8) -> Poly {
        let bytes = shake256(seed + [nonce], outputByteCount: eta * n / 4)
        return cbd2(bytes)
    }

    private static func cbd2(_ buffer: [UInt8]) -> Poly {
        var r = Poly()
        for i in 0..<(n / 8) {
            let t = load32(buffer, 4 * i)
            var d = t & 0x55555555
            d &+= (t >> 1) & 0x55555555
            for j in 0..<8 {
                let a = Int16((d >> UInt32(4 * j)) & 0x3)
                let b = Int16((d >> UInt32(4 * j + 2)) & 0x3)
                r.coeffs[8 * i + j] = a - b
            }
        }
        return r
    }

    private static func load32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(bytes[offset])
            | (UInt32(bytes[offset + 1]) << 8)
            | (UInt32(bytes[offset + 2]) << 16)
            | (UInt32(bytes[offset + 3]) << 24)
    }

    private static func polyVecCompressDU(_ a: PolyVec) -> [UInt8] {
        var out = [UInt8]()
        out.reserveCapacity(polyVecCompressedBytesDU)
        for p in a.vec {
            out += polyCompressDU(p)
        }
        return out
    }

    private static func polyVecDecompressDU(_ bytes: [UInt8]) -> PolyVec {
        var out = PolyVec()
        for i in 0..<k {
            out.vec[i] = polyDecompressDU(Array(bytes[(i * polyCompressedBytesDU)..<((i + 1) * polyCompressedBytesDU)]))
        }
        return out
    }

    private static func polyCompressDU(_ a: Poly) -> [UInt8] {
        var r = [UInt8](repeating: 0, count: polyCompressedBytesDU)
        for j in 0..<(n / 4) {
            var t = [UInt16](repeating: 0, count: 4)
            for i in 0..<4 {
                t[i] = scalarCompressD10(a.coeffs[4 * j + i])
            }
            r[5 * j + 0] = UInt8(truncatingIfNeeded: t[0] >> 0)
            r[5 * j + 1] = UInt8(truncatingIfNeeded: (t[0] >> 8) | ((t[1] << 2) & 0xff))
            r[5 * j + 2] = UInt8(truncatingIfNeeded: (t[1] >> 6) | ((t[2] << 4) & 0xff))
            r[5 * j + 3] = UInt8(truncatingIfNeeded: (t[2] >> 4) | ((t[3] << 6) & 0xff))
            r[5 * j + 4] = UInt8(truncatingIfNeeded: t[3] >> 2)
        }
        return r
    }

    private static func polyDecompressDU(_ bytes: [UInt8]) -> Poly {
        var r = Poly()
        for j in 0..<(n / 4) {
            let base = 5 * j
            let t0 = UInt16(bytes[base]) | (UInt16(bytes[base + 1]) << 8)
            let t1 = (UInt16(bytes[base + 1]) >> 2) | (UInt16(bytes[base + 2]) << 6)
            let t2 = (UInt16(bytes[base + 2]) >> 4) | (UInt16(bytes[base + 3]) << 4)
            let t3 = (UInt16(bytes[base + 3]) >> 6) | (UInt16(bytes[base + 4]) << 2)
            r.coeffs[4 * j + 0] = scalarDecompressD10(t0 & 0x03ff)
            r.coeffs[4 * j + 1] = scalarDecompressD10(t1 & 0x03ff)
            r.coeffs[4 * j + 2] = scalarDecompressD10(t2 & 0x03ff)
            r.coeffs[4 * j + 3] = scalarDecompressD10(t3 & 0x03ff)
        }
        return r
    }

    private static func polyCompressDV(_ a: Poly) -> [UInt8] {
        var r = [UInt8](repeating: 0, count: polyCompressedBytesDV)
        for i in 0..<(n / 8) {
            var t = [UInt8](repeating: 0, count: 8)
            for j in 0..<8 {
                t[j] = scalarCompressD4(a.coeffs[8 * i + j])
            }
            r[4 * i + 0] = t[0] | (t[1] << 4)
            r[4 * i + 1] = t[2] | (t[3] << 4)
            r[4 * i + 2] = t[4] | (t[5] << 4)
            r[4 * i + 3] = t[6] | (t[7] << 4)
        }
        return r
    }

    private static func polyDecompressDV(_ bytes: [UInt8]) -> Poly {
        var r = Poly()
        for i in 0..<(n / 2) {
            r.coeffs[2 * i + 0] = scalarDecompressD4(bytes[i] & 0x0f)
            r.coeffs[2 * i + 1] = scalarDecompressD4((bytes[i] >> 4) & 0x0f)
        }
        return r
    }

    private static func scalarCompressD1(_ u: Int16) -> UInt8 {
        let d0 = UInt32(UInt16(bitPattern: u)) &* 1_290_168
        return UInt8((d0 &+ (1 << 30)) >> 31)
    }

    private static func scalarCompressD4(_ u: Int16) -> UInt8 {
        let d0 = UInt32(UInt16(bitPattern: u)) &* 1_290_160
        return UInt8((d0 &+ (1 << 27)) >> 28)
    }

    private static func scalarDecompressD4(_ u: UInt8) -> Int16 {
        Int16((((UInt32(u) * UInt32(qInt)) + 8) >> 4))
    }

    private static func scalarCompressD10(_ u: Int16) -> UInt16 {
        var d0 = UInt64(UInt16(bitPattern: u)) * 2_642_263_040
        d0 = (d0 + (1 << 32)) >> 33
        return UInt16(d0 & 0x03ff)
    }

    private static func scalarDecompressD10(_ u: UInt16) -> Int16 {
        Int16((((UInt32(u) * UInt32(qInt)) + 512) >> 10))
    }

    private static func polyVecToBytes(_ a: PolyVec) -> [UInt8] {
        var out = [UInt8]()
        out.reserveCapacity(polyVecBytes)
        for p in a.vec {
            out += polyToBytes(p)
        }
        return out
    }

    private static func polyVecFromBytes(_ bytes: [UInt8]) -> PolyVec {
        var r = PolyVec()
        for i in 0..<k {
            r.vec[i] = polyFromBytes(Array(bytes[(i * polyBytes)..<((i + 1) * polyBytes)]))
        }
        return r
    }

    private static func polyToBytes(_ a: Poly) -> [UInt8] {
        var r = [UInt8](repeating: 0, count: polyBytes)
        for i in 0..<(n / 2) {
            let t0 = UInt16(bitPattern: a.coeffs[2 * i])
            let t1 = UInt16(bitPattern: a.coeffs[2 * i + 1])
            r[3 * i + 0] = UInt8(truncatingIfNeeded: t0)
            r[3 * i + 1] = UInt8(truncatingIfNeeded: (t0 >> 8) | (t1 << 4))
            r[3 * i + 2] = UInt8(truncatingIfNeeded: t1 >> 4)
        }
        return r
    }

    private static func polyFromBytes(_ bytes: [UInt8]) -> Poly {
        var r = Poly()
        for i in 0..<(n / 2) {
            let b0 = UInt16(bytes[3 * i])
            let b1 = UInt16(bytes[3 * i + 1])
            let b2 = UInt16(bytes[3 * i + 2])
            r.coeffs[2 * i + 0] = Int16((b0 | (b1 << 8)) & 0x0fff)
            r.coeffs[2 * i + 1] = Int16(((b1 >> 4) | (b2 << 4)) & 0x0fff)
        }
        return r
    }

    private static func polyFromMessage(_ message: [UInt8]) -> Poly {
        var r = Poly()
        for i in 0..<32 {
            for j in 0..<8 {
                let bit = (message[i] >> UInt8(j)) & 1
                r.coeffs[8 * i + j] = bit == 1 ? 1665 : 0
            }
        }
        return r
    }

    private static func polyToMessage(_ a: Poly) -> [UInt8] {
        var msg = [UInt8](repeating: 0, count: 32)
        for i in 0..<32 {
            for j in 0..<8 {
                msg[i] |= scalarCompressD1(a.coeffs[8 * i + j]) << UInt8(j)
            }
        }
        return msg
    }

    private static func polyVecNTT(_ v: inout PolyVec) {
        for i in 0..<k {
            polyNTT(&v.vec[i])
        }
    }

    private static func polyVecInvNTT(_ v: inout PolyVec) {
        for i in 0..<k {
            polyInvNTT(&v.vec[i])
        }
    }

    private static func polyVecToMont(_ v: inout PolyVec) {
        for i in 0..<k {
            polyToMont(&v.vec[i])
        }
    }

    private static func polyVecReduce(_ v: inout PolyVec) {
        for i in 0..<k {
            polyReduce(&v.vec[i])
        }
    }

    private static func polyVecAdd(_ v: inout PolyVec, _ b: PolyVec) {
        for i in 0..<k {
            polyAdd(&v.vec[i], b.vec[i])
        }
    }

    private static func polyAdd(_ r: inout Poly, _ b: Poly) {
        for i in 0..<n {
            r.coeffs[i] = Int16(Int32(r.coeffs[i]) + Int32(b.coeffs[i]))
        }
    }

    private static func polySub(_ r: inout Poly, _ b: Poly) {
        for i in 0..<n {
            r.coeffs[i] = Int16(Int32(r.coeffs[i]) - Int32(b.coeffs[i]))
        }
    }

    private static func polyReduce(_ r: inout Poly) {
        for i in 0..<n {
            let t = barrettReduce(r.coeffs[i])
            r.coeffs[i] = t < 0 ? t + q : t
        }
    }

    private static func polyToMont(_ r: inout Poly) {
        for i in 0..<n {
            r.coeffs[i] = fqmul(r.coeffs[i], 1353)
        }
    }

    private static func polyNTT(_ p: inout Poly) {
        for layer in 1...7 {
            var zetaIndex = 1 << (layer - 1)
            let len = n >> layer
            var start = 0
            while start < n {
                let zeta = zetas[zetaIndex]
                zetaIndex += 1
                for j in start..<(start + len) {
                    let t = fqmul(p.coeffs[j + len], zeta)
                    p.coeffs[j + len] = Int16(Int32(p.coeffs[j]) - Int32(t))
                    p.coeffs[j] = Int16(Int32(p.coeffs[j]) + Int32(t))
                }
                start += 2 * len
            }
        }
    }

    private static func polyInvNTT(_ p: inout Poly) {
        for j in 0..<n {
            p.coeffs[j] = fqmul(p.coeffs[j], 1441)
        }
        for layer in stride(from: 7, through: 1, by: -1) {
            let len = n >> layer
            var zetaIndex = (1 << layer) - 1
            var start = 0
            while start < n {
                let zeta = zetas[zetaIndex]
                zetaIndex -= 1
                for j in start..<(start + len) {
                    let t = p.coeffs[j]
                    p.coeffs[j] = barrettReduce(Int16(Int32(t) + Int32(p.coeffs[j + len])))
                    p.coeffs[j + len] = Int16(Int32(p.coeffs[j + len]) - Int32(t))
                    p.coeffs[j + len] = fqmul(p.coeffs[j + len], zeta)
                }
                start += 2 * len
            }
        }
    }

    private static func polyVecMulcacheCompute(_ v: PolyVec) -> PolyVecMulcache {
        var cache = PolyVecMulcache()
        for i in 0..<k {
            cache.vec[i] = polyMulcacheCompute(v.vec[i])
        }
        return cache
    }

    private static func polyMulcacheCompute(_ a: Poly) -> PolyMulcache {
        var cache = PolyMulcache()
        for i in 0..<(n / 4) {
            cache.coeffs[2 * i + 0] = fqmul(a.coeffs[4 * i + 1], zetas[64 + i])
            cache.coeffs[2 * i + 1] = fqmul(a.coeffs[4 * i + 3], -zetas[64 + i])
        }
        return cache
    }

    private static func polyVecBaseMulAcc(_ a: PolyVec, _ b: PolyVec, _ bCache: PolyVecMulcache) -> Poly {
        var r = Poly()
        for i in 0..<(n / 2) {
            var t0: Int32 = 0
            var t1: Int32 = 0
            for j in 0..<k {
                t0 += Int32(a.vec[j].coeffs[2 * i + 1]) * Int32(bCache.vec[j].coeffs[i])
                t0 += Int32(a.vec[j].coeffs[2 * i]) * Int32(b.vec[j].coeffs[2 * i])
                t1 += Int32(a.vec[j].coeffs[2 * i]) * Int32(b.vec[j].coeffs[2 * i + 1])
                t1 += Int32(a.vec[j].coeffs[2 * i + 1]) * Int32(b.vec[j].coeffs[2 * i])
            }
            r.coeffs[2 * i] = montgomeryReduce(t0)
            r.coeffs[2 * i + 1] = montgomeryReduce(t1)
        }
        return r
    }

    private static func fqmul(_ a: Int16, _ b: Int16) -> Int16 {
        montgomeryReduce(Int32(a) * Int32(b))
    }

    private static func montgomeryReduce(_ a: Int32) -> Int16 {
        let aReduced = UInt16(truncatingIfNeeded: a)
        let aInverted = aReduced &* 62209
        let t = Int16(bitPattern: aInverted)
        let r = (a - Int32(t) * Int32(q)) >> 16
        return Int16(r)
    }

    private static func barrettReduce(_ a: Int16) -> Int16 {
        let t = (20159 * Int32(a) + (1 << 25)) >> 26
        return Int16(Int32(a) - t * Int32(q))
    }

    private static func constantTimeCompare(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<lhs.count {
            diff |= lhs[i] ^ rhs[i]
        }
        return diff == 0
    }

    private static func sha3_256(_ input: [UInt8]) -> [UInt8] {
        Keccak.hash(input, outputByteCount: 32, rate: 136, domain: 0x06)
    }

    private static func sha3_512(_ input: [UInt8]) -> [UInt8] {
        Keccak.hash(input, outputByteCount: 64, rate: 72, domain: 0x06)
    }

    private static func shake256(_ input: [UInt8], outputByteCount: Int) -> [UInt8] {
        Keccak.hash(input, outputByteCount: outputByteCount, rate: 136, domain: 0x1f)
    }

    private struct Shake128XOF {
        private var state: [UInt64]

        init(input: [UInt8]) {
            state = Keccak.absorb(input, rate: xofRate, domain: 0x1f)
        }

        mutating func squeezeBlocks(_ blockCount: Int) -> [UInt8] {
            var out = [UInt8]()
            out.reserveCapacity(blockCount * xofRate)
            for _ in 0..<blockCount {
                Keccak.permute(&state)
                out += Keccak.extractBytes(state, offset: 0, count: xofRate)
            }
            return out
        }
    }

    private enum Keccak {
        static func hash(_ input: [UInt8], outputByteCount: Int, rate: Int, domain: UInt8) -> [UInt8] {
            var state = absorb(input, rate: rate, domain: domain)
            var out = [UInt8]()
            out.reserveCapacity(outputByteCount)
            while out.count < outputByteCount {
                permute(&state)
                out += extractBytes(state, offset: 0, count: min(rate, outputByteCount - out.count))
            }
            return out
        }

        static func absorb(_ input: [UInt8], rate: Int, domain: UInt8) -> [UInt64] {
            var state = [UInt64](repeating: 0, count: 25)
            var offset = 0
            var remaining = input.count
            while remaining >= rate {
                xorBytes(&state, input, inputOffset: offset, stateOffset: 0, count: rate)
                permute(&state)
                offset += rate
                remaining -= rate
            }
            if remaining > 0 {
                xorBytes(&state, input, inputOffset: offset, stateOffset: 0, count: remaining)
            }
            xorByte(&state, domain, offset: remaining)
            xorByte(&state, 0x80, offset: rate - 1)
            return state
        }

        private static func xorBytes(_ state: inout [UInt64], _ input: [UInt8], inputOffset: Int, stateOffset: Int, count: Int) {
            for i in 0..<count {
                xorByte(&state, input[inputOffset + i], offset: stateOffset + i)
            }
        }

        private static func xorByte(_ state: inout [UInt64], _ byte: UInt8, offset: Int) {
            let lane = offset / 8
            let shift = UInt64((offset % 8) * 8)
            state[lane] ^= UInt64(byte) << shift
        }

        static func extractBytes(_ state: [UInt64], offset: Int, count: Int) -> [UInt8] {
            var out = [UInt8](repeating: 0, count: count)
            for i in 0..<count {
                let byteOffset = offset + i
                let lane = byteOffset / 8
                let shift = UInt64((byteOffset % 8) * 8)
                out[i] = UInt8((state[lane] >> shift) & 0xff)
            }
            return out
        }

        static func permute(_ state: inout [UInt64]) {
            for round in 0..<24 {
                var c = [UInt64](repeating: 0, count: 5)
                var d = [UInt64](repeating: 0, count: 5)
                for x in 0..<5 {
                    c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
                }
                for x in 0..<5 {
                    d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotatedLeft(1)
                }
                for x in 0..<5 {
                    for y in 0..<5 {
                        state[x + 5 * y] ^= d[x]
                    }
                }

                var b = [UInt64](repeating: 0, count: 25)
                for x in 0..<5 {
                    for y in 0..<5 {
                        let index = x + 5 * y
                        b[y + 5 * ((2 * x + 3 * y) % 5)] = state[index].rotatedLeft(rho[index])
                    }
                }

                for x in 0..<5 {
                    for y in 0..<5 {
                        state[x + 5 * y] = b[x + 5 * y] ^ ((~b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y])
                    }
                }
                state[0] ^= roundConstants[round]
            }
        }

        private static let rho: [Int] = [
            0, 1, 62, 28, 27,
            36, 44, 6, 55, 20,
            3, 10, 43, 25, 39,
            41, 45, 15, 21, 8,
            18, 2, 61, 56, 14
        ]

        private static let roundConstants: [UInt64] = [
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
            0x0000000080000001, 0x8000000080008008
        ]
    }

    private static let zetas: [Int16] = [
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
        -308, 996, 991, 958, -1460, 1522, 1628
    ]
}

private extension UInt64 {
    func rotatedLeft(_ amount: Int) -> UInt64 {
        amount == 0 ? self : (self << UInt64(amount)) | (self >> UInt64(64 - amount))
    }
}
