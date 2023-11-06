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

import Foundation
import CryptoKit

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

enum KeyPairType: String {
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
    
    init?(from string: String) {
        let uppercased = string.uppercased();
        if let value = KeyPairType(rawValue: uppercased) {
            self = value
        } else {
            return nil
        }
    }
    
    // Initializer that tries to create an enum from a prefix byte
    init(fromPrefixByte prefixByte: UInt8) {
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
            // If the byte does not match any case, return nil
            self = .operator }
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

enum KeyPairError: Error {
    case invalidSeedLength(String)
    case invalidPrefix(String)
    case decodingError(String)
    case randomBytesError(String)
    case invalidRawBytesLength(String)
}

struct KeyPair {
    let keyPairType: KeyPairType
    let publicKey: Curve25519.Signing.PublicKey
    let privateKey: Curve25519.Signing.PrivateKey
   
    /// Explicit default initializer.
    init(keyPairType: KeyPairType, publicKey: Curve25519.Signing.PublicKey, privateKey: Curve25519.Signing.PrivateKey) {
        self.keyPairType = keyPairType
        self.publicKey = publicKey
        self.privateKey = privateKey
    }
    
    /// Initializer that creates [KeyPair] from random bytes.
    init(keyPairType: KeyPairType) throws {
        guard let randomBytes =  generateSeedRandom() else {
            throw KeyPairError.randomBytesError("Failed to generate random bytes")
        }
        let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: randomBytes)
        self = KeyPair(keyPairType: keyPairType, publicKey: signingKey.publicKey, privateKey: signingKey.self)
    }
    
    /// Initializer that creates [KeyPair] from provided [Data]. It has to be 32 bytes long.
    init(keyPairType: KeyPairType, rawBytes: Data) throws  {
        guard rawBytes.count == 32 else {
            throw KeyPairError.invalidRawBytesLength("Raw bytes data has to be of 32 lenght")
        }
        let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: rawBytes)
        self = KeyPair(keyPairType: keyPairType, publicKey: signingKey.publicKey, privateKey: signingKey.self)
    }
    
    /// Initlializer that creates [KeyPair] from provided seed.
    init(seed: String) throws {
        guard seed.count == Constants.encodedSeedLength else {
            throw KeyPairError.invalidSeedLength("Bad seed length: \(seed.count)")
        }
        
        guard let raw = Data(base64Encoded: seed) else {
                throw KeyPairError.decodingError("Failed to decode base32 string")
            }

        let b1 = raw[0] & 248
        guard b1 == Constants.prefixByteSeed else {
                throw KeyPairError.invalidPrefix("Incorrect byte prefix: \(raw[0])")
            }

            let b2 = (raw[0] & 7) << 5 | (raw[1] & 248) >> 3
            let kpType = KeyPairType(fromPrefixByte: b2)
            let seed = raw[2...] // Extract the seed part from the raw bytes.
        
        let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        
        self =  KeyPair(keyPairType: kpType, publicKey: signingKey.publicKey, privateKey: signingKey.self)
    }
    
    /// Attempts to sign the given input with the key pair's seed
    func sign(input: Data) throws -> Data {
        try self.privateKey.signature(for: input)
    }
}

func generateSeedRandom() -> Data? {
    var bytes = [UInt8](repeating: 0, count: 32)
    let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    guard status == errSecSuccess else { return nil }
    return Data(bytes)
}
