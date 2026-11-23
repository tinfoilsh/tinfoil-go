import Foundation
import TinfoilGo

// Type-check the supported Swift-facing API. Nothing here runs: CI only invokes
// swiftc -typecheck, so this proves the surface exists with the expected
// signatures, and nothing more.
//
// In particular it cannot detect a change to the JSON contract — the CodingKeys
// below are string literals with no link to the Go struct that produces them.
// The VerificationResult type below records the Swift side of that shape; the
// Go side is resultJSON in mobile/verification.go, whose doc says to update
// this file when it changes.
func checkMobileSurface() throws {
    var error: NSError?
    let _: Int64 = MobileVerificationSchemaVersion

    // Options travel as JSON (see mobile/options.go). An empty string selects
    // the default policy.
    let _: String = MobilePublicRegistryID
    guard let verifier = MobileNewVerifier("{}", &error) else {
        if let error { throw error }
        return
    }

    // A config authorizer is a Swift object that Go calls back during
    // verify. gomobile also emits a proxy class named MobileConfigAuthorizer,
    // so Swift imports the protocol as MobileConfigAuthorizerProtocol.
    guard let _ = MobileNewVerifierWithConfigAuthorizer("", SmokeAuthorizer(), &error) else {
        if let error { throw error }
        return
    }

    // The caller fetches the document itself, with a fresh nonce per fetch. A
    // relay is a host with an optional port, not a URL; "" fetches directly.
    guard let nonce = MobileNewNonce() else { return }
    let _: String = MobileAttestationURL("enclave.example", "relay.example:8443", nonce, &error)
    if let error { throw error }

    // Checks a client makes before any I/O.
    let _: Bool = verifier.callerAuthorizesConfig()
    try verifier.checkPinVerifiability("org/repo", project: "")

    // Verifying performs no I/O; it appraises the fetched bytes. Both an
    // accepted and a rejected document return a result with the report; only
    // an error without a report, such as a usage error, is thrown.
    let payload: String = verifier.verify(Data(), nonce: nonce, repo: "org/repo", project: "", error: &error)
    if let error { throw error }
    _ = try decodeVerificationResult(payload)

    // Errors cross as NSError with only a message; the prefix is the category.
    let _: [String] = [
        MobileUsageErrorPrefix,
        MobileVerificationErrorPrefix,
    ]
}

final class SmokeAuthorizer: NSObject, MobileConfigAuthorizerProtocol {
    func authorizeConfig(_ endorsementJSON: String?) throws {
        throw NSError(domain: "smoke", code: 1, userInfo: [NSLocalizedDescriptionKey: "rejected"])
    }
}

/// The fields a caller is expected to find in a verification result.
/// `mobile/verification.go` owns the shape; this mirrors it so the Swift side
/// of the contract is written down next to the surface that carries it.
struct VerificationResult: Decodable {
    let schemaVersion: Int
    let report: Report
    let error: RejectionError?

    struct RejectionError: Decodable {
        let layer: String
        let message: String
    }

    struct Report: Decodable {
        let steps: [Step]
        let verifiedFacts: VerifiedFacts?
        let partialFacts: PartialFacts?
        let metadata: Metadata

        private enum CodingKeys: String, CodingKey {
            case steps, metadata
            case verifiedFacts = "verified_facts"
            case partialFacts = "partial_facts"
        }
    }

    struct Step: Decodable {
        let layer: String
        let status: String
        let message: String?
    }

    struct Metadata: Decodable {
        let verifiedAt: String

        private enum CodingKeys: String, CodingKey {
            case verifiedAt = "verified_at"
        }
    }

    struct PartialFacts: Decodable {
        let expected: ExpectedFacts?
        let measured: MeasuredFacts?
    }

    struct ExpectedFacts: Decodable {
        let configRepo: String
        let artifact: VerifiedFacts.Artifact
        let config: VerifiedFacts.Config?
        let platform: VerifiedFacts.Artifact?
        let codeMeasurement: VerifiedFacts.Measurement?
        let measurement: VerifiedFacts.Measurement?

        private enum CodingKeys: String, CodingKey {
            case artifact, config, platform, measurement
            case configRepo = "config_repo"
            case codeMeasurement = "code_measurement"
        }
    }

    struct MeasuredFacts: Decodable {
        let cpuMeasurement: VerifiedFacts.Measurement?
        let tlsPublicKeyFP: String?
        let hpkePublicKeyFP: String?

        private enum CodingKeys: String, CodingKey {
            case cpuMeasurement = "cpu_measurement"
            case tlsPublicKeyFP = "tls_public_key_fp"
            case hpkePublicKeyFP = "hpke_public_key_fp"
        }
    }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case report, error
    }
}

struct VerifiedFacts: Decodable {
    let configRepo: String
    let codeDigest: String
    let codeTag: String?
    let codeMeasurement: Measurement?
    let enclaveMeasurement: Measurement?
    let config: Config?
    let runtime: Artifact?
    let platform: Artifact?
    let tlsPublicKeyFP: String
    let hpkePublicKey: String?
    let cryptoMaterial: [CryptoMaterial]
    let freshnessExpiresAt: String

    struct Measurement: Decodable {
        let type: String
        let registers: [String]
    }

    struct Config: Decodable {
        let source: String
        let name: String?
        let digest: String
        let reference: String?
        let signingKeyHint: String?
        let approvalTime: String?
        let registryID: String?
        let signatureTime: String?

        private enum CodingKeys: String, CodingKey {
            case source, name, digest, reference
            case signingKeyHint = "signing_key_hint"
            case approvalTime = "approval_time"
            case registryID = "registry_id"
            case signatureTime = "signature_time"
        }
    }

    struct Artifact: Decodable {
        let source: String
        let repo: String?
        let tag: String?
        let digest: String
        let name: String?
        let commit: String?
        let approvalTime: String?

        private enum CodingKeys: String, CodingKey {
            case source, repo, tag, digest, name, commit
            case approvalTime = "approval_time"
        }
    }

    struct CryptoMaterial: Decodable {
        let id: String
        let format: String
        let data: String
    }

    private enum CodingKeys: String, CodingKey {
        case configRepo = "config_repo"
        case codeDigest = "code_digest"
        case codeTag = "code_tag"
        case codeMeasurement = "code_measurement"
        case enclaveMeasurement = "enclave_measurement"
        case config, runtime, platform
        case tlsPublicKeyFP = "tls_public_key_fp"
        case hpkePublicKey = "hpke_public_key"
        case cryptoMaterial = "crypto_material"
        case freshnessExpiresAt = "freshness_expires_at"
    }
}

func decodeVerificationResult(_ payload: String) throws -> VerificationResult {
    try JSONDecoder().decode(VerificationResult.self, from: Data(payload.utf8))
}
