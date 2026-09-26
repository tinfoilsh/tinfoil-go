import Foundation
import Tinfoil

// Type-check the supported Swift-facing API. Nothing here runs: CI only invokes
// swiftc -typecheck, so this proves the surface exists with the expected
// signatures, and nothing more.
//
// In particular it cannot detect a change to the JSON contract — the CodingKeys
// below are string literals with no link to the Go struct that produces them.
// The Verification type below records the Swift side of that shape; the Go side
// is verificationJSON in mobile/verification.go, whose doc says to update this
// file when it changes.
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

    // Verifying contacts an enclave, so this is a signature check only.
    let _: String = client.verify(&error)
    if let error { throw error }

    // Empty before this client has verified, rather than an error.
    let cached = client.verification(&error)
    if let error { throw error }
    _ = try decodeVerification(cached)
}

/// The fields a caller is expected to find in a verification payload.
/// `mobile/verification.go` owns the shape; this mirrors it so the Swift side
/// of the contract is written down next to the surface that carries it.
struct Verification: Decodable {
    let schemaVersion: Int
    let configRepo: String
    let enclaveHost: String?
    let codeDigest: String
    let codeTag: String?
    let codeMeasurement: Measurement?
    let enclaveMeasurement: Measurement?
    let tlsPublicKeyFP: String
    let hpkePublicKey: String?
    let cryptoMaterial: [CryptoMaterial]
    let freshnessExpiresAt: String
    let verifiedAt: String
    let verifier: SoftwareIdentity

    struct Measurement: Decodable {
        let type: String
        let registers: [String]
    }

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
        case codeMeasurement = "code_measurement"
        case enclaveMeasurement = "enclave_measurement"
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
