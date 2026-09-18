import Tinfoil

// Compile the supported Swift-facing API without contacting an enclave.
func checkClientSurface() throws {
    guard let client = ClientNewSecureClient("enclave.example", "org/repo") else {
        return
    }
    let _: String = client.enclave()
    let _: String = client.repo()
    let _: String = ClientVersion
    _ = try client.groundTruthJSON()
    _ = try client.verificationDocumentJSON()
    _ = client.groundTruth()
    _ = client.verificationDocument()
}
