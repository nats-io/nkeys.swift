// Copyright 2023 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Base32
import Foundation
import Sodium

struct Constants {
    static let encodedSeedLength: Int = 58

    static let prefixByteSeed: UInt8 = 18 << 3
    static let prefixBytePrivate: UInt8 = 15 << 3
    static let prefixByteServer: UInt8 = 13 << 3
    static let prefixByteCluster: UInt8 = 2 << 3
    static let prefixByteOperator: UInt8 = 14 << 3
    static let prefixByteModule: UInt8 = 12 << 3
    static let prefixByteAccount: UInt8 = 0
    static let prefixByteUser: UInt8 = 20 << 3
    static let prefixByteService: UInt8 = 21 << 3
    static let prefixByteUnknown: UInt8 = 23 << 3

    static let ed25519SignatureByteSize = 64

    static let publicKeyPrefixes: [UInt8] = [
        prefixByteAccount,
        prefixByteCluster,
        prefixByteOperator,
        prefixByteServer,
        prefixByteUser,
        prefixByteModule,
        prefixByteService,
    ]
}

/// Represents the type of KeyPair
public enum KeyPairType: String {
    /// A server identity
    case server = "SERVER"
    /// A cluster (group of servers) identity
    case cluster = "CLUSTER"
    /// An operator (vouches for accounts) identity
    case `operator` = "OPERATOR"
    /// An account (vouches for users) identity
    case account = "ACCOUNT"
    /// A user identity
    case user = "USER"
    /// A module identity - can represent an opaque component, etc.
    case module = "MODULE"
    /// A service / service provider identity
    case service = "SERVICE"

    /// Initilizer that tries to create a KeyPair from its String representation.
    public init(from string: String) throws {
        let uppercased = string.uppercased()
        if let value = KeyPairType(rawValue: uppercased) {
            self = value
        } else {
            throw NkeysErrors.failedKeyPairTypeInit("could not create a KeyPairType from \(string)")
        }
    }

    /// Initializer that tries to create an enum from a prefix byte
    public init(fromPrefixByte prefixByte: UInt8) throws {
        switch prefixByte {
        case Constants.prefixByteServer:
            self = .server
        case Constants.prefixByteCluster:
            self = .cluster
        case Constants.prefixByteOperator:
            self = .operator
        case Constants.prefixByteAccount:
            self = .account
        case Constants.prefixByteUser:
            self = .user
        case Constants.prefixByteModule:
            self = .module
        case Constants.prefixByteService:
            self = .service
        default:
            throw NkeysErrors.failedKeyPairGeneration(
                "failed to init KeyPairType from \(prefixByte)")

        }
    }

    func getPrefixByte() -> UInt8 {
        switch self {
        case .server:
            return Constants.prefixByteServer
        case .cluster:
            return Constants.prefixByteCluster
        case .operator:
            return Constants.prefixByteOperator
        case .account:
            return Constants.prefixByteAccount
        case .user:
            return Constants.prefixByteUser
        case .module:
            return Constants.prefixByteModule
        case .service:
            return Constants.prefixByteService
        }
    }
}

/// NkeysErrors represents all possible errors when working with NKeys library
public enum NkeysErrors: Error {
    case invalidSeedLength(String)
    case invalidPrefix(String)
    case decodingError(String)
    case randomBytesError(String)
    case invalidRawBytesLength(String)
    case missingPrivateKey(String)
    case invalidChecksum(String)
    case invalidKeyPair(String)
    case invalidSignatureSize(String)
    case verificationFailed(String)
    case failedKeyPairGeneration(String)
    case signingFailed(String)
    case failedKeyPairTypeInit(String)
}

/// KeyPair represents ED25519 Key Pair. It can contain either the pair, or just the public key which can be used when user needs just to verify a signature.
public struct KeyPair {
    let keyPairType: KeyPairType
    let publicKey: Sign.PublicKey
    private let keyPair: Sign.KeyPair?
    private let sodium: Sodium

    /// Initializer that creates [KeyPair] from random bytes.
    public init(keyPairType: KeyPairType) throws {
        self.sodium = Sodium()
        guard let keyPair = self.sodium.sign.keyPair() else {
            throw NkeysErrors.randomBytesError("Can't generate random bytes")
        }
        self.keyPair = keyPair
        self.keyPairType = keyPairType
        self.publicKey = keyPair.publicKey
    }

    /// Initlializer that creates [KeyPair] from provided seed.
    public init(seed: String) throws {
        guard seed.count == Constants.encodedSeedLength else {
            throw NkeysErrors.invalidSeedLength("Bad seed length: \(seed.count)")
        }

        // TODO: We should not upwrap here
        let raw = try decodeRaw(seed.data(using: .utf8)!)

        let b1 = raw[0] & 248
        guard b1 == Constants.prefixByteSeed else {
            throw NkeysErrors.invalidPrefix("Incorrect byte prefix: \(raw[0])")
        }

        let b2 = (raw[0] & 7) << 5 | ((raw[1] & 248) >> 3)
        let kpType = try KeyPairType(fromPrefixByte: b2)
        let seed = raw[2...]  // Extract the seed part from the raw bytes.
        let bytes: [UInt8] = Array(seed)
        let sodium = Sodium()
        self.sodium = sodium
        guard let kp = sodium.sign.keyPair(seed: bytes) else {
            throw NkeysErrors.failedKeyPairGeneration("Failed to generate key pair from seed")
        }
        self.keyPairType = kpType
        self.keyPair = kp
        self.publicKey = kp.publicKey
    }

    /// Attempts to create a KeyPair containing only public key that can be used to verify signatures.
    public init(publicKey: String) throws {
        var raw = try decodeRaw(publicKey.data(using: .utf8)!)

        let prefix = raw[0]
        if !Constants.publicKeyPrefixes.contains(prefix) {
            throw NkeysErrors.invalidPrefix("Not a valid public key prefix \(prefix)")
        }
        raw.remove(at: 0)
        self.sodium = Sodium()
        let rawBytes: [UInt8] = Array(raw)
        self.publicKey = rawBytes
        self.keyPairType = try KeyPairType.init(fromPrefixByte: prefix)
        self.keyPair = nil
    }

    /// Attempts to sign the given input with the key pair's seed.
    public func sign(input: Data) throws -> Data {
        guard let keyPar = self.keyPair else {
            throw NkeysErrors.missingPrivateKey("Can't sign PublicKey only KeyPair")
        }
        let inputBytes: [UInt8] = Array(input)
        guard
            let signature = self.sodium.sign.signature(
                message: inputBytes, secretKey: keyPar.secretKey)
        else {
            throw NkeysErrors.signingFailed("failed to sign the message")
        }
        return Data(signature)
    }

    /// Verifies signature for provided input.
    public func verify(input: Data, signature sig: Data) throws {
        guard sig.count == Constants.ed25519SignatureByteSize else {
            throw NkeysErrors.invalidSignatureSize(
                "Signature size should be \(Constants.ed25519SignatureByteSize) but is \(sig.count)"
            )
        }
        if self.sodium.sign.verify(
            message: [UInt8](input), publicKey: self.publicKey, signature: [UInt8](sig))
        {
            return
        } else {
            throw NkeysErrors.verificationFailed("signature is not valid for given input")
        }
    }

    /// Returns base32 encoded public key.
    public var publicKeyEncoded: String {
        var raw = Data()
        raw.append(self.keyPairType.getPrefixByte())
        raw.append(contentsOf: self.publicKey)
        pushCRC(data: &raw)
        return base32Encode(raw, padding: false)
    }

    /// Returns encoded seed.
    public var seed: String {
        get throws {
            guard let seed = self.keyPair?.secretKey else {
                throw NkeysErrors.invalidKeyPair(
                    "Can't return seed from KeyPair with Public Key only")
            }
            var raw = Data()
            let prefixBytes = self.keyPairType.getPrefixByte()

            let b1 = Constants.prefixByteSeed | prefixBytes >> 5
            let b2 = (prefixBytes & 31) << 3

            raw.append(b1)
            raw.append(b2)
            raw.append(contentsOf: seed[0..<32])
            pushCRC(data: &raw)

            return raw.base32EncodedStringNoPadding
        }
    }

}

func decodeRaw(_ data: Data) throws -> Data {
    var decoded = data.base32DecodedData!
    let checksum = extractCRC(data: &decoded)

    let validChecksjm = validChecksum(data: decoded, expected: checksum)
    if !validChecksjm {
        throw NkeysErrors.invalidChecksum("Checksum mismatch")
    }
    return decoded
}
