import Foundation
import Tinfoil

// Compile the supported Swift-facing API without contacting an enclave.
func checkClientSurface(document: Data, nonce: Data) throws {
    var error: NSError?
    let options = ClientParseVerificationOptionsJSON("{}", &error)
    if let error { throw error }
    guard let client = ClientNewSecureClient("enclave.example", "org/repo", options, &error) else {
        if let error { throw error }
        return
    }
    let _: String = client.enclave()
    let _: String = client.repo()
    let _: String = ClientVersion
    _ = client.verificationJSON(&error)
    if let error { throw error }
    _ = client.verification()
    _ = ClientNewDefaultClient(options, &error)
    if let error { throw error }
    let result = ClientVerifyDocumentV3JSON(document, nonce, "org/repo", options, &error)
    if let error { throw error }
    let _: Any = try JSONSerialization.jsonObject(with: Data(result.utf8))
}
