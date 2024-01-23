import XCTest
@testable import NKeys

final class nkeys_swiftTests: XCTestCase {

    func test_seedEncodeDecodeRoundtrip() throws {
        let pair = try KeyPair.init(keyPairType: KeyPairType.user)
        let seed = try pair.seed
        let pub = pair.publicKeyEncoded

        let pair2 = try KeyPair.init(seed: seed)
        let seed2 = try pair2.seed

        XCTAssert(seed == seed2)
        XCTAssert(pub == pair2.publicKeyEncoded)
    }

    func test_signAndVerify() throws {
        let pair = try KeyPair(keyPairType: KeyPairType.user)
        let message = "A very secret message".data(using: .utf8)!

        let signature = try pair.sign(input: message)
        try pair.verify(input: message, signature: signature)
    }

    func test_roundtrip_encoding_go_compatibility() throws {

        let seed = "SAAPN4W3EG6KCJGUQTKTJ5GSB5NHK5CHAJL4DBGFUM3HHROI4XUEP4OBK4";
        let pk = "ACODERUVFFAWZQDSS6SBIACUA5O6SXF7HJ3YTYXBALHZP3P7R4BUO4J2";

        let pair = try KeyPair(seed: seed)

        let swift_seed = try pair.seed
        XCTAssert(seed == swift_seed)
        XCTAssert(pk == pair.publicKeyEncoded)
    }
}
