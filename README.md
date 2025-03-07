# Tinfoil Go Client

Tinfoil's secure HTTP client.

[![Build Status](https://github.com/tinfoilsh/tinfoil-go/workflows/Run%20tests/badge.svg)](https://github.com/tinfoilsh/tinfoil-go/actions)

## Installation

```bash
go get github.com/tinfoilsh/tinfoil-go
```

## Quick Start: Use the Secure HTTP Client

```go
import (
    "fmt"
    "github.com/tinfoilsh/tinfoil-go"
)

// Create a client for a specific enclave and code repository
client := tinfoil.NewSecureClient("enclave.example.com", "org/repo")

// Make HTTP requests - verification happens automatically
resp, err := client.Get("/api/data", nil)
if err != nil {
    return fmt.Errorf("request failed: %w", err)
}

// POST with headers and body
headers := map[string]string{"Content-Type": "application/json"}
body := []byte(`{"key": "value"}`)
resp, err := client.Post("/api/submit", headers, body)
```

See [Secure HTTP Client](#secure-http-client) for examples of how to use the secure client.


# Secure HTTP Client

The secure HTTP client ensures all requests are made to a verified enclave. This client:
- Verifies the enclave's attestation before making requests
- Pins TLS connections to the attested certificate

### Security Properties

| Property | Description |
|----------|-------------|
| **Code Verification** | Ensures enclave runs the expected code version |
| **Connection Security** | TLS with certificate pinning prevents MITM attacks |
| **Request Isolation** | Each client connects to exactly one enclave |

### Usage Examples

```go
// 1. Create a client
client := tinfoil.NewSecureClient(
    "enclave.example.com",  // Enclave hostname
    "org/repo",            // GitHub repository
)

// 2. Manual verification (optional)
state, err := client.Verify()
if err != nil {
    return fmt.Errorf("verification failed: %w", err)
}

// 3. Make HTTP requests
resp, err := client.Get("/api/status", map[string]string{
    "Authorization": "Bearer token",
})

// 4. Use response
if resp.StatusCode == http.StatusOK {
    var data MyData
    json.Unmarshal(resp.Body, &data)
}

// 5. Get raw HTTP client (advanced usage)
httpClient, err := client.HTTPClient()
if err != nil {
    return fmt.Errorf("failed to get HTTP client: %w", err)
}
```

## Foreign Function Interface (FFI) Support

For usage in other languages through FFI, additional functions are available:

```go
// Initialize a request and get an ID
requestID, err := client.InitPostRequest("/api/submit", []byte(`{"key":"value"}`))

// Add headers individually
client.AddHeader(requestID, "Content-Type", "application/json")
client.AddHeader(requestID, "Authorization", "Bearer token")

// Execute the request
resp, err := client.ExecuteRequest(requestID)
```

##  Reporting Vulnerabilities

Please report security vulnerabilities by either:
- Emailing [contact@tinfoil.sh](mailto:contact@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to security reports within 24 hours and will keep you updated on our progress.
