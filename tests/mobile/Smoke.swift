import Foundation
import Tinfoil

// Compile the supported Swift-facing API without contacting an enclave.
//
// Everything structured crosses as JSON, so this also decodes a verification
// payload: gomobile drops what it cannot represent without failing the build,
// and a type-check that only touched the method names would not notice.
func checkMobileSurface() throws {
    var error: NSError?

    guard let client = MobileNewClient("enclave.example", "org/repo", &error) else {
        if let error { throw error }
        return
    }
    let _: String = client.enclave()
    let _: String = client.repo()
    let _: String = MobileVersion
    let _: Int64 = MobileVerificationSchemaVersion

    // Options travel as JSON: pinned_registers, and freshness_max_age_ns in
    // integer nanoseconds. An empty string selects the default policy.
    _ = MobileNewClientWithOptions("enclave.example", "org/repo", "{}", &error)
    if let error { throw error }

    // Empty before this client has verified, rather than an error.
    let cached = client.verification(&error)
    if let error { throw error }
    if !cached.isEmpty {
        _ = try decodeVerification(cached)
    }
}

/// The fields a caller is expected to find in a verification payload. Decoding
/// here is what pins the contract: `verifier/mobile/verification.go` owns the
/// shape, and this fails if a key it promises goes missing.
struct Verification: Decodable {
    let schemaVersion: Int
    let configRepo: String
    let enclaveHost: String?
    let codeDigest: String
    let codeTag: String?
    let tlsPublicKeyFP: String
    let hpkePublicKey: String?
    let cryptoMaterial: [CryptoMaterial]
    let freshnessExpiresAt: String
    let verifiedAt: String
    let verifier: SoftwareIdentity

    struct CryptoMaterial: Decodable {
        let id: String
        let format: String
        let data: String
    }

    struct SoftwareIdentity: Decodable {
        let name: String
        let version: String
    }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case configRepo = "config_repo"
        case enclaveHost = "enclave_host"
        case codeDigest = "code_digest"
        case codeTag = "code_tag"
        case tlsPublicKeyFP = "tls_public_key_fp"
        case hpkePublicKey = "hpke_public_key"
        case cryptoMaterial = "crypto_material"
        case freshnessExpiresAt = "freshness_expires_at"
        case verifiedAt = "verified_at"
        case verifier
    }
}

func decodeVerification(_ payload: String) throws -> Verification {
    try JSONDecoder().decode(Verification.self, from: Data(payload.utf8))
}
