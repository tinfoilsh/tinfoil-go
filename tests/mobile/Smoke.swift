import Foundation
import Tinfoil

// Compile the supported Swift-facing API without contacting an enclave.
func checkClientSurface() throws {
    guard let client = ClientNewSecureClient("enclave.example", "org/repo", nil) else {
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
