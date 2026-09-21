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

func checkWorkloadPinSurface() throws {
    let registerHexLength = 96
    let register = String(repeating: "a", count: registerHexLength)
    let raw = """
    {"pinned_code":{"tdx_measurement":{"rtmr1":"\(register)","rtmr2":"\(register)"}},
     "pinned_shape":{"cpus":4,"memory_mb":8192,"disks":1},"freshness_max_age_ns":3600000000000}
    """
    var error: NSError?
    let options = ClientParseVerificationOptionsJSON(raw, &error)
    if let error { throw error }
    guard let client = ClientNewSecureClient("enclave.example", "", options, &error) else {
        if let error { throw error }
        fatalError("Workload pin construction returned no client")
    }
    precondition(client.enclave() == "enclave.example")
    precondition(client.repo().isEmpty)
    precondition(client.verification() == nil)

    error = nil
    let invalid = ClientParseVerificationOptionsJSON("{\"pinned_shape\":{\"memoryMB\":8192}}", &error)
    precondition(invalid == nil && error != nil)
}

try checkWorkloadPinSurface()
