import Foundation
import Tinfoil

// Compile the supported Swift-facing API without contacting an enclave.
func checkClientSurface() throws {
    guard let client = ClientNewSecureClient("enclave.example", "org/repo") else {
        return
    }
    let _: String = client.enclave()
    let _: String = client.repo()
    let _: String = ClientVersion
    var error: NSError?
    _ = client.groundTruthJSON(&error)
    if let error { throw error }
    _ = client.verificationDocumentJSON(&error)
    if let error { throw error }
    _ = client.groundTruth()
    _ = client.verificationDocument()
}

func checkVerificationOptions(document: Data, nonce: Data) throws {
    let options = #"{"freshness_max_age_ns":86400000000000,"pinned_registers":{"type":"https://tinfoil.sh/predicate/tdx-guest/v2","registers":["","","","","000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"]}}"#
    var error: NSError?
    _ = ClientNewSecureClientWithOptionsJSON("enclave.example", "org/repo", options, &error)
    if let error { throw error }
    _ = ClientNewDefaultClientWithOptionsJSON(options, &error)
    if let error { throw error }
    let result = ClientVerifyDocumentV3WithOptionsJSON(document, nonce, "org/repo", options, &error)
    if let error { throw error }
    let _: Any = try JSONSerialization.jsonObject(with: Data(result.utf8))
}
